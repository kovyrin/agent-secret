package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type recordingLauncher struct {
	launches launchWatcher
	mu       sync.Mutex
	launched []approval.ApprovalRequestPayload
	expected approval.ExpectedApprover
	err      error
}

type blockingLauncher struct {
	started chan struct{}
}

type exitingLauncher struct {
	launches launchWatcher
	expected approval.ExpectedApprover
	exited   chan error
}

type sequenceLauncher struct {
	launches launchWatcher
	mu       sync.Mutex
	launched []approval.ApprovalRequestPayload
	expected []approval.ExpectedApprover
}

type contextObservingLauncher struct {
	launches launchWatcher
	expected approval.ExpectedApprover
	canceled chan struct{}
}

type launchWatcher struct {
	mu    sync.Mutex
	cond  *sync.Cond
	count int
}

type recordingSignatureVerifier struct {
	pathTeamID    string
	processTeamID string
	pathErr       error
	processErr    error
	paths         []string
	pids          []int
}

func (v *recordingSignatureVerifier) VerifyPath(path string) (string, error) {
	v.paths = append(v.paths, path)
	if v.pathErr != nil {
		return "", v.pathErr
	}
	return v.pathTeamID, nil
}

func (v *recordingSignatureVerifier) VerifyProcess(pid int) (string, error) {
	v.pids = append(v.pids, pid)
	if v.processErr != nil {
		return "", v.processErr
	}
	return v.processTeamID, nil
}

func (l *recordingLauncher) Launch(
	_ context.Context,
	_ string,
	payload approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, payload)
	if l.err != nil {
		return approval.ExpectedApprover{}, l.err
	}
	l.launches.record()
	return l.expected, nil
}

func (l *recordingLauncher) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}

func (l *recordingLauncher) waitForLaunch(ctx context.Context, count int) error {
	return l.launches.wait(ctx, count)
}

func newBlockingLauncher() *blockingLauncher {
	return &blockingLauncher{
		started: make(chan struct{}),
	}
}

func (l *blockingLauncher) Launch(
	ctx context.Context,
	_ string,
	_ approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	close(l.started)
	<-ctx.Done()
	return approval.ExpectedApprover{}, ctx.Err()
}

func (l *exitingLauncher) Launch(
	_ context.Context,
	_ string,
	_ approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	l.launches.record()
	expected := l.expected
	expected.Exited = l.exited
	return expected, nil
}

func (l *exitingLauncher) waitForLaunch(ctx context.Context, count int) error {
	return l.launches.wait(ctx, count)
}

func (l *sequenceLauncher) Launch(
	_ context.Context,
	_ string,
	payload approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, payload)
	index := len(l.launched) - 1
	if index >= len(l.expected) {
		index = len(l.expected) - 1
	}
	l.launches.record()
	return l.expected[index], nil
}

func (l *sequenceLauncher) waitForLaunch(ctx context.Context, count int) error {
	return l.launches.wait(ctx, count)
}

func (l *contextObservingLauncher) Launch(
	ctx context.Context,
	_ string,
	_ approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	l.launches.record()
	go func() {
		<-ctx.Done()
		close(l.canceled)
	}()
	return l.expected, nil
}

func (l *contextObservingLauncher) waitForLaunch(ctx context.Context, count int) error {
	return l.launches.wait(ctx, count)
}

func (w *launchWatcher) record() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initLocked()
	w.count++
	w.cond.Broadcast()
}

func (w *launchWatcher) wait(ctx context.Context, count int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initLocked()
	stop := context.AfterFunc(ctx, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.cond.Broadcast()
	})
	defer stop()
	for w.count < count {
		if err := ctx.Err(); err != nil {
			return err
		}
		w.cond.Wait()
	}
	return ctx.Err()
}

func (w *launchWatcher) initLocked() {
	if w.cond == nil {
		w.cond = sync.NewCond(&w.mu)
	}
}

func TestApprovalFixturesDecodeInGo(t *testing.T) {
	t.Parallel()

	requestData := readFixture(t, "approval_request.json")
	var approvalRequest approval.ApprovalRequestPayload
	if err := json.Unmarshal(requestData, &approvalRequest); err != nil {
		t.Fatalf("decode approval request fixture: %v", err)
	}
	if approvalRequest.RequestID != "req_123" || approvalRequest.Nonce != "nonce_456" {
		t.Fatalf("unexpected approval request identifiers: %+v", approvalRequest)
	}
	if approvalRequest.Secrets[0].Ref != "op://Example Vault/Example Item/token" {
		t.Fatalf("unexpected secret ref: %+v", approvalRequest.Secrets)
	}
	if approvalRequest.Secrets[0].Account != "Work" {
		t.Fatalf("unexpected secret account: %+v", approvalRequest.Secrets)
	}

	decisionData := readFixture(t, "approval_decision.json")
	var decision approval.ApprovalDecisionPayload
	if err := json.Unmarshal(decisionData, &decision); err != nil {
		t.Fatalf("decode approval decision fixture: %v", err)
	}
	if decision.Decision != approval.ApprovalDecisionApproveReusable || decision.ReusableUses == nil || *decision.ReusableUses != 3 {
		t.Fatalf("unexpected approval decision: %+v", decision)
	}
}

func TestApprovalPayloadEncodesCurrentProtocolFields(t *testing.T) {
	t.Parallel()

	payload := approval.NewRequestPayload(testCorrelation("req_123", "nonce_456"), request.ExecRequest{
		Reason:    "Run tests",
		Command:   []string{"/usr/bin/true"},
		CWD:       "/tmp/project",
		ExpiresAt: time.Unix(1_800_000_000, 0).UTC(),
	})
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal approval payload: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode approval payload object: %v", err)
	}
	for _, field := range []string{"override_env", "overridden_aliases", "allow_mutable_executable", "reusable_uses"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("approval payload omitted current protocol field %q: %s", field, data)
		}
	}
	if got := string(fields["overridden_aliases"]); got != "[]" {
		t.Fatalf("overridden_aliases should encode as an empty array, got %s", got)
	}
}

func TestSocketApproverLaunchesAndAcceptsExpectedPeerDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	req.ReusableUses = 2

	resultCh := make(chan approval.Decision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	payload := fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	if payload.RequestID != "req_1" || payload.Nonce != "nonce_1" {
		t.Fatalf("unexpected payload identifiers: %+v", payload)
	}
	if payload.Secrets[0].Account != "Work" {
		t.Fatalf("payload secret account = %q, want Work", payload.Secrets[0].Account)
	}
	if payload.ReusableUses != 2 {
		t.Fatalf("payload reusable uses = %d, want request count 2", payload.ReusableUses)
	}
	uses := payload.ReusableUses
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID:    "req_1",
		Nonce:        "nonce_1",
		Decision:     approval.ApprovalDecisionApproveReusable,
		ReusableUses: &uses,
	})
	if err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}

	select {
	case decision := <-resultCh:
		if !decision.Approved || !decision.Reusable {
			t.Fatalf("unexpected approval result: %+v", decision)
		}
		if decision.ReusableUses != 2 {
			t.Fatalf("decision reusable uses = %d, want 2", decision.ReusableUses)
		}
	case err := <-errCh:
		t.Fatalf("ApproveExec returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval result")
	}
}

func TestSocketApproverRejectsReusableUseCountMismatch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	resultCh := make(chan approval.Decision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	payload := fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	mismatchedUses := payload.ReusableUses + 1
	var err error
	for _, decision := range []approval.ApprovalDecisionPayload{
		{
			RequestID: "req_1",
			Nonce:     "nonce_1",
			Decision:  approval.ApprovalDecisionApproveReusable,
		},
		{
			RequestID:    "req_1",
			Nonce:        "nonce_1",
			Decision:     approval.ApprovalDecisionApproveReusable,
			ReusableUses: &mismatchedUses,
		},
	} {
		err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), decision)
		if !errors.Is(err, protocol.ErrMalformedEnvelope) {
			t.Fatalf("SubmitDecision reusable count mismatch error = %v, want malformed envelope", err)
		}
	}

	uses := payload.ReusableUses
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID:    "req_1",
		Nonce:        "nonce_1",
		Decision:     approval.ApprovalDecisionApproveReusable,
		ReusableUses: &uses,
	})
	if err != nil {
		t.Fatalf("SubmitDecision matching reusable count returned error: %v", err)
	}

	select {
	case decision := <-resultCh:
		if !decision.Approved || !decision.Reusable {
			t.Fatalf("unexpected approval result: %+v", decision)
		}
	case err := <-errCh:
		t.Fatalf("ApproveExec returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval result")
	}
}

func TestSocketApproverRejectsWrongPeerAndStaleNonce(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	fetchPendingErrorForTest(t, launcher, approver, peerInfoForTest(t, os.Getpid()+1, exe), approval.ErrApproverPeerMismatch)
	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "wrong",
		Decision:  approval.ApprovalDecisionApproveOnce,
	})
	if !errors.Is(err, approval.ErrStaleApproval) {
		t.Fatalf("expected stale approval error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionDeny,
	})
	if err != nil {
		t.Fatalf("SubmitDecision deny returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, approval.ErrApprovalDenied) {
		t.Fatalf("ApproveExec error = %v, want denial", err)
	}
}

func TestSocketApproverRejectsFetchFromWrongApproverProcessSignature(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "OTHERTEAM",
	}
	launcher := &recordingLauncher{
		expected: approval.ExpectedApprover{
			PID:               os.Getpid(),
			ExecutablePath:    exe,
			ExpectedTeamID:    "TEAMID",
			VerifySignature:   true,
			SignatureVerifier: verifier,
		},
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(ctx, testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()

	fetchPendingErrorForTest(t, launcher, approver, peerInfoForTest(t, os.Getpid(), exe), approval.ErrApproverPeerMismatch)
	if !slices.Equal(verifier.pids, []int{os.Getpid()}) {
		t.Fatalf("verified pids = %v, want [%d]", verifier.pids, os.Getpid())
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("ApproveExec error = %v, want context cancellation", err)
	}
}

func TestSocketApproverRejectsDecisionFromWrongApproverProcessSignature(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	verifier := &recordingSignatureVerifier{
		pathTeamID:    "TEAMID",
		processTeamID: "TEAMID",
	}
	launcher := &recordingLauncher{
		expected: approval.ExpectedApprover{
			PID:               os.Getpid(),
			ExecutablePath:    exe,
			ExpectedTeamID:    "TEAMID",
			VerifySignature:   true,
			SignatureVerifier: verifier,
		},
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(ctx, testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()

	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	verifier.processTeamID = "OTHERTEAM"
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionApproveOnce,
	})
	if !errors.Is(err, approval.ErrApproverPeerMismatch) {
		t.Fatalf("expected approver peer mismatch, got %v", err)
	}
	if !slices.Equal(verifier.pids, []int{os.Getpid(), os.Getpid()}) {
		t.Fatalf("verified pids = %v, want [%d %d]", verifier.pids, os.Getpid(), os.Getpid())
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("ApproveExec error = %v, want context cancellation", err)
	}
}

func TestSocketApproverFIFOAndQueuedExpiry(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	now := time.Date(2026, 4, 28, 16, 0, 0, 0, time.UTC)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, func() time.Time { return now })
	first := approvalTestRequest(t, now.Add(time.Minute))
	expiredSecond := approvalTestRequest(t, now.Add(-time.Second))

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), first)
		firstErr <- err
	}()
	payload := fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_2", "nonce_2"), expiredSecond)
		secondErr <- err
	}()

	if payload.RequestID != "req_1" {
		t.Fatalf("FIFO displayed request %q first", payload.RequestID)
	}
	if err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionApproveOnce,
	}); err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("first approval returned error: %v", err)
	}
	if err := <-secondErr; !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("second approval error = %v, want expired", err)
	}
	if launcher.Count() != 1 {
		t.Fatalf("expired queued request launched approver; launches=%d", launcher.Count())
	}
}

func TestSocketApproverExpiresActiveRequestWithoutDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	approver := newSocketApproverForTest(t, launcher, func() time.Time { return now })
	req := approvalTestRequest(t, now)

	_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverFailsWhenExpectedApproverExitsBeforeFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	exited := make(chan error, 1)
	launcher := &exitingLauncher{
		expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		exited:   exited,
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	fetchPendingErrorForTest(t, launcher, approver, peerInfoForTest(t, os.Getpid()+1, exe), approval.ErrApproverPeerMismatch)

	exited <- errors.New("exit status 64")
	close(exited)

	if err := receiveApprovalError(t, errCh, "ApproveExec did not observe early approver exit"); !errors.Is(err, approval.ErrApproverLaunchFailed) {
		t.Fatalf("ApproveExec error = %v, want launch failure", err)
	}
	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); !errors.Is(err, approval.ErrNoPendingApproval) {
		t.Fatalf("FetchPending after early exit = %v, want no pending approval", err)
	}
}

func TestSocketApproverFailsWhenExpectedApproverExitsAfterFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	exited := make(chan error, 1)
	launcher := &exitingLauncher{
		expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		exited:   exited,
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	resultCh := make(chan approval.Decision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()

	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	exited <- errors.New("exit status 64")
	close(exited)

	if err := receiveApprovalError(t, errCh, "ApproveExec did not observe post-fetch approver exit"); !errors.Is(err, approval.ErrApproverLaunchFailed) {
		t.Fatalf("ApproveExec error = %v, want launch failure", err)
	}
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionApproveOnce,
	})
	if !errors.Is(err, approval.ErrNoPendingApproval) {
		t.Fatalf("SubmitDecision after approver exit = %v, want no pending approval", err)
	}
	select {
	case decision := <-resultCh:
		t.Fatalf("ApproveExec returned decision after approver exit: %+v", decision)
	default:
	}
}

func TestSocketApproverPromotesNextRequestWhenApproverExitsAfterFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	firstExited := make(chan error, 1)
	launcher := &sequenceLauncher{
		expected: []approval.ExpectedApprover{
			{PID: os.Getpid(), ExecutablePath: exe, Exited: firstExited},
			{PID: os.Getpid(), ExecutablePath: exe},
		},
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	firstReq := approvalTestRequest(t, time.Now().Add(time.Minute))
	secondReq := approvalTestRequest(t, time.Now().Add(time.Minute))
	firstErr := make(chan error, 1)
	secondResult := make(chan approval.Decision, 1)
	secondErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), firstReq)
		firstErr <- err
	}()
	payload := fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	go func() {
		decision, err := approver.ApproveExec(context.Background(), testCorrelation("req_2", "nonce_2"), secondReq)
		if err != nil {
			secondErr <- err
			return
		}
		secondResult <- decision
	}()

	if payload.RequestID != "req_1" {
		t.Fatalf("first payload request ID = %q, want req_1", payload.RequestID)
	}
	firstExited <- errors.New("exit status 64")
	close(firstExited)
	if err := receiveApprovalError(t, firstErr, "first ApproveExec did not observe approver exit"); !errors.Is(err, approval.ErrApproverLaunchFailed) {
		t.Fatalf("first ApproveExec error = %v, want launch failure", err)
	}

	payload = fetchPendingForTest(t, launcher, 2, approver, peerInfoForTest(t, os.Getpid(), exe))
	if payload.RequestID != "req_2" {
		t.Fatalf("second payload request ID = %q, want req_2", payload.RequestID)
	}
	if err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_2",
		Nonce:     "nonce_2",
		Decision:  approval.ApprovalDecisionApproveOnce,
	}); err != nil {
		t.Fatalf("SubmitDecision second request returned error: %v", err)
	}
	select {
	case decision := <-secondResult:
		if !decision.Approved {
			t.Fatalf("unexpected second approval result: %+v", decision)
		}
	case err := <-secondErr:
		t.Fatalf("second ApproveExec returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second approval result")
	}
}

func TestSocketApproverLaunchContextLivesUntilApprovalCompletes(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &contextObservingLauncher{
		expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		canceled: make(chan struct{}),
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	fetchPendingErrorForTest(t, launcher, approver, peerInfoForTest(t, os.Getpid()+1, exe), approval.ErrApproverPeerMismatch)

	select {
	case <-launcher.canceled:
		t.Fatal("launch context was canceled before approval completed")
	default:
	}

	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionApproveOnce,
	})
	if err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}
	if err := receiveApprovalError(t, errCh, "ApproveExec did not complete"); err != nil {
		t.Fatalf("ApproveExec returned error: %v", err)
	}
	receiveApprovalSignal(t, launcher.canceled, "launch context was not canceled after approval completed")
}

func TestSocketApproverFetchPendingHonorsContextWhileApproverLaunchIsBlocked(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := newBlockingLauncher()
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	approveCtx, cancelApprove := context.WithCancel(context.Background())
	defer cancelApprove()
	approveErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(approveCtx, testCorrelation("req_1", "nonce_1"), req)
		approveErr <- err
	}()
	receiveApprovalSignal(t, launcher.started, "approver launch did not start")

	fetchCtx, cancelFetch := context.WithCancel(context.Background())
	fetchErr := make(chan error, 1)
	go func() {
		_, err := approver.FetchPending(fetchCtx, peerInfoForTest(t, os.Getpid(), exe))
		fetchErr <- err
	}()
	cancelFetch()
	if err := receiveApprovalError(t, fetchErr, "FetchPending did not observe context cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchPending error = %v, want context cancellation", err)
	}

	cancelApprove()
	if err := receiveApprovalError(t, approveErr, "ApproveExec did not observe context cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ApproveExec error = %v, want context cancellation", err)
	}
}

func TestSocketApproverSubmitDecisionHonorsContextWhileApproverLaunchIsBlocked(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := newBlockingLauncher()
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	approveCtx, cancelApprove := context.WithCancel(context.Background())
	defer cancelApprove()
	approveErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(approveCtx, testCorrelation("req_1", "nonce_1"), req)
		approveErr <- err
	}()
	receiveApprovalSignal(t, launcher.started, "approver launch did not start")

	decisionCtx, cancelDecision := context.WithCancel(context.Background())
	decisionErr := make(chan error, 1)
	go func() {
		decisionErr <- approver.SubmitDecision(
			decisionCtx,
			peerInfoForTest(t, os.Getpid(), exe),
			approval.ApprovalDecisionPayload{
				RequestID: "req_1",
				Nonce:     "nonce_1",
				Decision:  approval.ApprovalDecisionApproveOnce,
			},
		)
	}()
	cancelDecision()
	if err := receiveApprovalError(t, decisionErr, "SubmitDecision did not observe context cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("SubmitDecision error = %v, want context cancellation", err)
	}

	cancelApprove()
	if err := receiveApprovalError(t, approveErr, "ApproveExec did not observe context cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ApproveExec error = %v, want context cancellation", err)
	}
}

func TestSocketApproverConstructorValidation(t *testing.T) {
	t.Parallel()

	if _, err := approval.NewSocketApprover("", &recordingLauncher{}, time.Now); err == nil {
		t.Fatal("expected missing socket path error")
	}
	if _, err := approval.NewSocketApprover("/tmp/agent-secret-test.sock", nil, time.Now); !errors.Is(err, approval.ErrApproverLaunchFailed) {
		t.Fatalf("expected launcher error, got %v", err)
	}
}

func TestSocketApproverRejectsInvalidDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))

	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionKind("banana"),
	})
	if !errors.Is(err, protocol.ErrMalformedEnvelope) {
		t.Fatalf("expected malformed decision error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionTimeout,
	})
	if err != nil {
		t.Fatalf("timeout decision returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverTreatsExpiredApprovalAsTimeout(t *testing.T) {
	t.Parallel()

	if err := submitExpiredDecisionForTest(t, approval.ApprovalDecisionApproveOnce); !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverPreservesExpiredDenial(t *testing.T) {
	t.Parallel()

	if err := submitExpiredDecisionForTest(t, approval.ApprovalDecisionDeny); !errors.Is(err, approval.ErrApprovalDenied) {
		t.Fatalf("ApproveExec error = %v, want denied", err)
	}
}

func submitExpiredDecisionForTest(t *testing.T, decision approval.ApprovalDecisionKind) error {
	t.Helper()

	exe := currentExecutable(t)
	now := time.Date(2026, 4, 28, 15, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	setNow := func(value time.Time) {
		nowMu.Lock()
		defer nowMu.Unlock()
		now = value
	}
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, nowFn)
	req := approvalTestRequest(t, now.Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	fetchPendingForTest(t, launcher, 1, approver, peerInfoForTest(t, os.Getpid(), exe))

	setNow(req.ExpiresAt)
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  decision,
	})
	if err != nil {
		t.Fatalf("expired %s decision returned error: %v", decision, err)
	}
	return <-errCh
}

func newSocketApproverForTest(t *testing.T, launcher approval.ApproverLauncher, now func() time.Time) *approval.SocketApprover {
	t.Helper()
	approver, err := approval.NewSocketApprover("/tmp/agent-secret-test.sock", launcher, now)
	if err != nil {
		t.Fatalf("approval.NewSocketApprover returned error: %v", err)
	}
	return approver
}

func approvalTestRequest(t *testing.T, expiresAt time.Time) request.ExecRequest {
	t.Helper()
	ref, err := request.ParseSecretRef("op://Example/Item/token")
	if err != nil {
		t.Fatalf("ParseSecretRef returned error: %v", err)
	}
	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: "/opt/homebrew/bin/terraform",
		ExecutableIdentity: fileidentity.Identity{Device: 1, Inode: 1, Mode: 0o755},
		CWD:                "/tmp/project",
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{
			"PATH=/opt/homebrew/bin",
			"NODE_OPTIONS=--require ./safe.js",
		}),
		Secrets:    []request.Secret{{Alias: "TOKEN", Ref: ref, Account: "Work"}},
		ReceivedAt: expiresAt.Add(-request.DefaultExecTTL),
		ExpiresAt:  expiresAt,
		TTL:        request.DefaultExecTTL,
	}
}

func peerInfoForTest(t *testing.T, pid int, exe string) peercred.Info {
	t.Helper()
	return peercred.Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            pid,
		ExecutablePath: exe,
		CWD:            "/tmp",
	}
}

func currentExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	return exe
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(
		filepath.Dir(file),
		"..",
		"..",
		"approver",
		"Tests",
		"AgentSecretApproverTests",
		"Fixtures",
		name,
	)
	//nolint:gosec // G304: test fixture path is derived from runtime.Caller within this repository.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

type launchWaiter interface {
	waitForLaunch(ctx context.Context, count int) error
}

func fetchPendingForTest(
	t *testing.T,
	launcher launchWaiter,
	launchCount int,
	approver *approval.SocketApprover,
	peer peercred.Info,
) approval.ApprovalRequestPayload {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := launcher.waitForLaunch(ctx, launchCount); err != nil {
		t.Fatalf("approver launch %d was not observed: %v", launchCount, err)
	}
	payload, err := approver.FetchPending(ctx, peer)
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	return payload
}

func fetchPendingErrorForTest(
	t *testing.T,
	launcher launchWaiter,
	approver *approval.SocketApprover,
	peer peercred.Info,
	want error,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := launcher.waitForLaunch(ctx, 1); err != nil {
		t.Fatalf("approver launch 1 was not observed: %v", err)
	}
	_, err := approver.FetchPending(ctx, peer)
	if !errors.Is(err, want) {
		t.Fatalf("FetchPending error = %v, want %v", err, want)
	}
}

func receiveApprovalSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func receiveApprovalError(t *testing.T, ch <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal(message)
		return nil
	}
}
