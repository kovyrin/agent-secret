package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrApproverLaunchFailed = errors.New("approver launch failed")
	ErrApproverIdentity     = errors.New("approver identity mismatch")
	ErrApproverPeerMismatch = errors.New("approver peer identity mismatch")
	ErrNoPendingApproval    = errors.New("no pending approval request")
	ErrStaleApproval        = errors.New("stale approval response")
)

type ApprovalRequestPayload struct {
	RequestID              string                    `json:"requestID"`
	Nonce                  string                    `json:"nonce"`
	Reason                 string                    `json:"reason"`
	Command                []string                  `json:"command"`
	CWD                    string                    `json:"cwd"`
	ResolvedExecutable     string                    `json:"resolvedExecutable,omitempty"`
	ExpiresAt              time.Time                 `json:"expiresAt"`
	Secrets                []ApprovalRequestedSecret `json:"secrets"`
	OverrideEnv            bool                      `json:"overrideEnv"`
	OverriddenAliases      []string                  `json:"overriddenAliases"`
	AllowMutableExecutable bool                      `json:"allowMutableExecutable"`
	ReusableUses           int                       `json:"reusableUses"`
}

type ApprovalRequestedSecret struct {
	Alias   string `json:"alias"`
	Ref     string `json:"ref"`
	Account string `json:"account,omitempty"`
}

type ApprovalDecisionKind string

const (
	ApprovalDecisionApproveOnce     ApprovalDecisionKind = "approve_once"
	ApprovalDecisionApproveReusable ApprovalDecisionKind = "approve_reusable"
	ApprovalDecisionDeny            ApprovalDecisionKind = "deny"
	ApprovalDecisionTimeout         ApprovalDecisionKind = "timeout"
)

type ApprovalDecisionPayload struct {
	RequestID    string               `json:"requestID"`
	Nonce        string               `json:"nonce"`
	Decision     ApprovalDecisionKind `json:"decision"`
	ReusableUses *int                 `json:"reusableUses,omitempty"`
}

type ApprovalEndpoint interface {
	FetchPending(ctx context.Context, peer peercred.Info) (ApprovalRequestPayload, error)
	SubmitDecision(ctx context.Context, peer peercred.Info, decision ApprovalDecisionPayload) error
}

type ApproverLauncher interface {
	Launch(ctx context.Context, socketPath string, payload ApprovalRequestPayload) (ExpectedApprover, error)
}

type ApproverIdentityPolicy interface {
	ValidateApproverExecutable(path string) (ApproverIdentity, error)
}

type ApproverIdentity struct {
	ExecutablePath  string
	BundlePath      string
	BundleID        string
	TeamID          string
	ExpectedTeamID  string
	VerifySignature bool
}

type ExpectedApprover struct {
	PID               int
	ExecutablePath    string
	ExpectedTeamID    string
	VerifySignature   bool
	signatureVerifier codeSignatureVerifier
	exited            <-chan error
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
	done          chan struct{}
	doneOnce      sync.Once
	expected      ExpectedApprover
	expectedReady bool
	expectedUsed  bool
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
	correlation protocol.Correlation,
	req request.ExecRequest,
) (ApprovalDecision, error) {
	job := &approvalJob{
		payload: approvalPayload(correlation, req),
		done:    make(chan struct{}),
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

func (a *SocketApprover) FetchPending(ctx context.Context, peer peercred.Info) (ApprovalRequestPayload, error) {
	job, err := a.activeWhenExpectedReady(ctx)
	if err != nil {
		return ApprovalRequestPayload{}, err
	}
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
	if !a.markExpectedUsed(job) {
		return ApprovalRequestPayload{}, ErrNoPendingApproval
	}
	return job.payload, nil
}

func (a *SocketApprover) SubmitDecision(
	ctx context.Context,
	peer peercred.Info,
	decision ApprovalDecisionPayload,
) error {
	job, err := a.activeWhenExpectedReady(ctx)
	if err != nil {
		return err
	}
	if job == nil {
		return ErrNoPendingApproval
	}
	if err := validateApproverPeer(job.expected, peer); err != nil {
		return err
	}
	if decision.RequestID != job.payload.RequestID || decision.Nonce != job.payload.Nonce {
		return ErrStaleApproval
	}
	switch decision.Decision {
	case ApprovalDecisionApproveOnce:
		if !a.now().Before(job.payload.ExpiresAt) {
			a.complete(job, approvalResult{err: ErrRequestExpired})
			return nil
		}
		a.complete(job, approvalResult{decision: ApprovalDecision{Approved: true}})
	case ApprovalDecisionApproveReusable:
		if !a.now().Before(job.payload.ExpiresAt) {
			a.complete(job, approvalResult{err: ErrRequestExpired})
			return nil
		}
		if err := validateReusableDecisionUses(decision, job.payload.ReusableUses); err != nil {
			return err
		}
		a.complete(job, approvalResult{decision: ApprovalDecision{
			Approved:     true,
			Reusable:     true,
			ReusableUses: job.payload.ReusableUses,
		}})
	case ApprovalDecisionDeny:
		a.complete(job, approvalResult{err: ErrApprovalDenied})
	case ApprovalDecisionTimeout:
		a.complete(job, approvalResult{err: ErrRequestExpired})
	default:
		return fmt.Errorf("%w: invalid approval decision %q", protocol.ErrMalformedEnvelope, decision.Decision)
	}
	return nil
}

func validateReusableDecisionUses(decision ApprovalDecisionPayload, expected int) error {
	if expected <= 0 {
		return fmt.Errorf("%w: invalid pending reusable use count %d", protocol.ErrMalformedEnvelope, expected)
	}
	if decision.ReusableUses == nil {
		return fmt.Errorf("%w: missing reusable use count", protocol.ErrMalformedEnvelope)
	}
	if *decision.ReusableUses != expected {
		return fmt.Errorf(
			"%w: reusable use count %d does not match pending request count %d",
			protocol.ErrMalformedEnvelope,
			*decision.ReusableUses,
			expected,
		)
	}
	return nil
}

func approvalPayload(correlation protocol.Correlation, req request.ExecRequest) ApprovalRequestPayload {
	secrets := make([]ApprovalRequestedSecret, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		secrets = append(secrets, ApprovalRequestedSecret{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	overriddenAliases := slices.Clone(req.OverriddenAliases)
	if overriddenAliases == nil {
		overriddenAliases = []string{}
	}
	return ApprovalRequestPayload{
		RequestID:              correlation.RequestID,
		Nonce:                  correlation.Nonce,
		Reason:                 req.Reason,
		Command:                slices.Clone(req.Command),
		CWD:                    req.CWD,
		ResolvedExecutable:     req.ResolvedExecutable,
		ExpiresAt:              req.ExpiresAt,
		Secrets:                secrets,
		OverrideEnv:            req.OverrideEnv,
		OverriddenAliases:      overriddenAliases,
		AllowMutableExecutable: req.AllowMutableExecutable,
		ReusableUses:           request.ReusableUsesOrDefault(req.ReusableUses),
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
	launchCtx := job.launchContext()
	expected, err := a.launcher.Launch(launchCtx, a.socketPath, job.payload)
	if err != nil {
		if job.canceled() {
			a.cancel(job, context.Canceled)
			return
		}
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
	if expected.exited != nil {
		go a.monitorExpectedApprover(job, expected.exited)
	}
}

func (a *SocketApprover) complete(job *approvalJob, result approvalResult) {
	job.cancel()
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
	job.cancel()
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

func (j *approvalJob) cancel() {
	j.doneOnce.Do(func() {
		close(j.done)
	})
}

func (j *approvalJob) canceled() bool {
	select {
	case <-j.done:
		return true
	default:
		return false
	}
}

func (j *approvalJob) launchContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-j.done
		cancel()
	}()
	return ctx
}

func (a *SocketApprover) markExpectedUsed(job *approvalJob) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != job {
		return false
	}
	job.expectedUsed = true
	return true
}

func (a *SocketApprover) monitorExpectedApprover(job *approvalJob, exited <-chan error) {
	select {
	case err := <-exited:
		message, shouldFail := a.expectedApproverExitFailure(job)
		if !shouldFail {
			return
		}
		if err != nil {
			message = fmt.Sprintf("%s: %v", message, err)
		}
		a.complete(job, approvalResult{err: fmt.Errorf("%w: %s", ErrApproverLaunchFailed, message)})
	case <-job.done:
	}
}

func (a *SocketApprover) expectedApproverExitFailure(job *approvalJob) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active != job || !job.expectedReady {
		return "", false
	}
	if job.expectedUsed {
		return "approver exited before submitting an approval decision", true
	}
	return "approver exited before fetching pending approval", true
}

func (a *SocketApprover) activeWhenExpectedReady(ctx context.Context) (*approvalJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	})
	defer stop()

	a.mu.Lock()
	defer a.mu.Unlock()
	for a.active != nil && !a.active.expectedReady {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.active, nil
}
