package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrApproverLaunchFailed = errors.New("approver launch failed")
	ErrApproverPeerMismatch = errors.New("approver peer identity mismatch")
	ErrNoPendingApproval    = errors.New("no pending approval request")
	ErrStaleApproval        = errors.New("stale approval response")
)

type ApprovalRequestPayload struct {
	RequestID          string                    `json:"requestID"`
	Nonce              string                    `json:"nonce"`
	Reason             string                    `json:"reason"`
	Command            []string                  `json:"command"`
	CWD                string                    `json:"cwd"`
	ResolvedExecutable string                    `json:"resolvedExecutable,omitempty"`
	ExpiresAt          time.Time                 `json:"expiresAt"`
	Secrets            []ApprovalRequestedSecret `json:"secrets"`
	OverrideEnv        bool                      `json:"overrideEnv"`
	OverriddenAliases  []string                  `json:"overriddenAliases,omitempty"`
	ReusableUses       int                       `json:"reusableUses"`
}

type ApprovalRequestedSecret struct {
	Alias string `json:"alias"`
	Ref   string `json:"ref"`
}

type ApprovalDecisionPayload struct {
	RequestID    string `json:"requestID"`
	Nonce        string `json:"nonce"`
	Decision     string `json:"decision"`
	ReusableUses *int   `json:"reusableUses,omitempty"`
}

type ApprovalEndpoint interface {
	FetchPending(ctx context.Context, peer peercred.Info) (ApprovalRequestPayload, error)
	SubmitDecision(ctx context.Context, peer peercred.Info, decision ApprovalDecisionPayload) error
}

type ApproverLauncher interface {
	Launch(ctx context.Context, socketPath string, payload ApprovalRequestPayload) (ExpectedApprover, error)
}

type ExpectedApprover struct {
	PID            int
	ExecutablePath string
}

type SocketApprover struct {
	mu         sync.Mutex
	cond       *sync.Cond
	now        func() time.Time
	socketPath string
	launcher   ApproverLauncher
	queue      []*approvalJob
	active     *approvalJob
}

type approvalJob struct {
	payload       ApprovalRequestPayload
	expected      ExpectedApprover
	expectedReady bool
	result        chan approvalResult
}

type approvalResult struct {
	decision ApprovalDecision
	err      error
}

func NewSocketApprover(socketPath string, launcher ApproverLauncher, now func() time.Time) (*SocketApprover, error) {
	if socketPath == "" {
		return nil, errors.New("approver socket path is required")
	}
	if launcher == nil {
		return nil, ErrApproverLaunchFailed
	}
	if now == nil {
		now = time.Now
	}
	approver := &SocketApprover{
		now:        now,
		socketPath: socketPath,
		launcher:   launcher,
	}
	approver.cond = sync.NewCond(&approver.mu)
	return approver, nil
}

func (a *SocketApprover) ApproveExec(
	ctx context.Context,
	requestID string,
	nonce string,
	req request.ExecRequest,
) (ApprovalDecision, error) {
	job := &approvalJob{
		payload: approvalPayload(requestID, nonce, req),
		result:  make(chan approvalResult, 1),
	}

	a.mu.Lock()
	a.queue = append(a.queue, job)
	shouldPromote := a.active == nil && len(a.queue) == 1
	a.mu.Unlock()
	if shouldPromote {
		go a.promoteNext()
	}

	timeout := job.payload.ExpiresAt.Sub(a.now())
	if timeout <= 0 {
		a.cancel(job, ErrRequestExpired)
		return ApprovalDecision{}, ErrRequestExpired
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-job.result:
		return result.decision, result.err
	case <-ctx.Done():
		a.cancel(job, ctx.Err())
		return ApprovalDecision{}, ctx.Err()
	case <-timer.C:
		a.cancel(job, ErrRequestExpired)
		return ApprovalDecision{}, ErrRequestExpired
	}
}

func (a *SocketApprover) FetchPending(_ context.Context, peer peercred.Info) (ApprovalRequestPayload, error) {
	a.mu.Lock()
	for a.active != nil && !a.active.expectedReady {
		a.cond.Wait()
	}
	job := a.active
	a.mu.Unlock()
	if job == nil {
		return ApprovalRequestPayload{}, ErrNoPendingApproval
	}
	if !a.now().Before(job.payload.ExpiresAt) {
		a.complete(job, approvalResult{err: ErrRequestExpired})
		return ApprovalRequestPayload{}, ErrRequestExpired
	}
	if err := validateApproverPeer(job.expected, peer); err != nil {
		return ApprovalRequestPayload{}, err
	}
	return job.payload, nil
}

func (a *SocketApprover) SubmitDecision(
	_ context.Context,
	peer peercred.Info,
	decision ApprovalDecisionPayload,
) error {
	a.mu.Lock()
	for a.active != nil && !a.active.expectedReady {
		a.cond.Wait()
	}
	job := a.active
	a.mu.Unlock()
	if job == nil {
		return ErrNoPendingApproval
	}
	if err := validateApproverPeer(job.expected, peer); err != nil {
		return err
	}
	if decision.RequestID != job.payload.RequestID || decision.Nonce != job.payload.Nonce {
		return ErrStaleApproval
	}
	if !a.now().Before(job.payload.ExpiresAt) || decision.Decision == "timeout" {
		a.complete(job, approvalResult{err: ErrRequestExpired})
		return nil
	}

	switch decision.Decision {
	case "approve_once":
		a.complete(job, approvalResult{decision: ApprovalDecision{Approved: true}})
	case "approve_reusable":
		a.complete(job, approvalResult{decision: ApprovalDecision{Approved: true, Reusable: true}})
	case "deny":
		a.complete(job, approvalResult{err: ErrApprovalDenied})
	default:
		return fmt.Errorf("%w: invalid approval decision %q", ErrMalformedEnvelope, decision.Decision)
	}
	return nil
}

type ProcessApproverLauncher struct {
	AppPath string
}

func (l ProcessApproverLauncher) Launch(ctx context.Context, socketPath string, _ ApprovalRequestPayload) (ExpectedApprover, error) {
	executable, err := l.executablePath()
	if err != nil {
		return ExpectedApprover{}, err
	}

	cmd := exec.CommandContext(ctx, executable, "--socket", socketPath)
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return ExpectedApprover{}, fmt.Errorf("%w: open /dev/null: %w", ErrApproverLaunchFailed, err)
	}
	defer func() { _ = devNull.Close() }()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := cmd.Start(); err != nil {
		return ExpectedApprover{}, fmt.Errorf("%w: %w", ErrApproverLaunchFailed, err)
	}
	expected := ExpectedApprover{
		PID:            cmd.Process.Pid,
		ExecutablePath: executable,
	}
	if err := cmd.Process.Release(); err != nil {
		return ExpectedApprover{}, fmt.Errorf("%w: release process: %w", ErrApproverLaunchFailed, err)
	}
	return expected, nil
}

func (l ProcessApproverLauncher) executablePath() (string, error) {
	if l.AppPath == "" {
		return defaultApproverPath()
	}
	if filepath.Ext(l.AppPath) == ".app" {
		for _, candidate := range approverExecutablesInApp(l.AppPath) {
			if executableExists(candidate) {
				return candidate, nil
			}
		}
		return approverExecutablesInApp(l.AppPath)[0], nil
	}
	return l.AppPath, nil
}

func approvalPayload(requestID string, nonce string, req request.ExecRequest) ApprovalRequestPayload {
	secrets := make([]ApprovalRequestedSecret, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		secrets = append(secrets, ApprovalRequestedSecret{Alias: secret.Alias, Ref: secret.Ref.Raw})
	}
	return ApprovalRequestPayload{
		RequestID:          requestID,
		Nonce:              nonce,
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		CWD:                req.CWD,
		ResolvedExecutable: req.ResolvedExecutable,
		ExpiresAt:          req.ExpiresAt,
		Secrets:            secrets,
		OverrideEnv:        req.OverrideEnv,
		OverriddenAliases:  slices.Clone(req.OverriddenAliases),
		ReusableUses:       3,
	}
}

func (a *SocketApprover) promoteNext() {
	a.mu.Lock()
	if a.active != nil || len(a.queue) == 0 {
		a.mu.Unlock()
		return
	}
	job := a.queue[0]
	a.queue = a.queue[1:]
	a.active = job
	a.mu.Unlock()

	if !a.now().Before(job.payload.ExpiresAt) {
		a.complete(job, approvalResult{err: ErrRequestExpired})
		return
	}
	expected, err := a.launcher.Launch(context.Background(), a.socketPath, job.payload)
	if err != nil {
		a.complete(job, approvalResult{err: fmt.Errorf("%w: %w", ErrApproverLaunchFailed, err)})
		return
	}

	a.mu.Lock()
	if a.active == job {
		job.expected = expected
		job.expectedReady = true
		a.cond.Broadcast()
	}
	a.mu.Unlock()
}

func (a *SocketApprover) complete(job *approvalJob, result approvalResult) {
	a.mu.Lock()
	if a.active == job {
		a.active = nil
	}
	a.cond.Broadcast()
	a.mu.Unlock()

	select {
	case job.result <- result:
	default:
	}
	go a.promoteNext()
}

func (a *SocketApprover) cancel(job *approvalJob, err error) {
	a.mu.Lock()
	for i, queued := range a.queue {
		if queued == job {
			a.queue = append(a.queue[:i], a.queue[i+1:]...)
			a.mu.Unlock()
			return
		}
	}
	if a.active == job {
		a.active = nil
	}
	a.cond.Broadcast()
	a.mu.Unlock()

	select {
	case job.result <- approvalResult{err: err}:
	default:
	}
	go a.promoteNext()
}

func validateApproverPeer(expected ExpectedApprover, got peercred.Info) error {
	if expected.PID != 0 && got.PID != expected.PID {
		return fmt.Errorf("%w: pid %d != %d", ErrApproverPeerMismatch, got.PID, expected.PID)
	}
	if expected.ExecutablePath == "" {
		return nil
	}
	expectedPath, err := comparableApproverPath(expected.ExecutablePath)
	if err != nil {
		return err
	}
	gotPath, err := comparableApproverPath(got.ExecutablePath)
	if err != nil {
		return err
	}
	if gotPath != expectedPath {
		return fmt.Errorf("%w: executable %q != %q", ErrApproverPeerMismatch, gotPath, expectedPath)
	}
	return nil
}

func comparableApproverPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("normalize approver path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

func defaultApproverPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("%w: get executable path: %w", ErrApproverLaunchFailed, err)
	}
	candidates := approverCandidatesForExecutable(exe)
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(
			home,
			"Applications",
			"AgentSecretApprover.app",
			"Contents",
			"MacOS",
			"agent-secret-approver",
		))
	}
	for _, candidate := range candidates {
		if executableExists(candidate) {
			return candidate, nil
		}
	}
	return candidates[0], nil
}

func approverCandidatesForExecutable(executable string) []string {
	executables := []string{executable}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil && resolved != executable {
		executables = append(executables, resolved)
	}

	candidates := make([]string, 0, len(executables)*3)
	seen := make(map[string]struct{})
	for _, candidate := range executables {
		for _, path := range []string{
			filepath.Join(filepath.Dir(candidate), "agent-secret-approver"),
			filepath.Clean(filepath.Join(filepath.Dir(candidate), "..", "..", "MacOS", "Agent Secret")),
			filepath.Clean(filepath.Join(
				filepath.Dir(candidate),
				"..",
				"..",
				"..",
				"..",
				"..",
				"MacOS",
				"Agent Secret",
			)),
		} {
			if _, ok := seen[path]; ok {
				continue
			}
			candidates = append(candidates, path)
			seen[path] = struct{}{}
		}
	}
	return candidates
}

func approverExecutablesInApp(appPath string) []string {
	return []string{
		filepath.Join(appPath, "Contents", "MacOS", "Agent Secret"),
		filepath.Join(appPath, "Contents", "MacOS", "agent-secret-approver"),
	}
}

func executableExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}
