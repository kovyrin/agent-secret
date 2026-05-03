package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type recordingLauncher struct {
	mu       sync.Mutex
	launched []ApprovalRequestPayload
	expected ExpectedApprover
	err      error
}

type blockingLauncher struct {
	started chan struct{}
}

type exitingLauncher struct {
	expected ExpectedApprover
	exited   chan error
}

type contextObservingLauncher struct {
	expected ExpectedApprover
	canceled chan struct{}
}

type allowApproverIdentityPolicy struct{}

func (allowApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	return ApproverIdentity{ExecutablePath: path}, nil
}

type staticApproverIdentityPolicy struct {
	identity ApproverIdentity
}

func (p staticApproverIdentityPolicy) ValidateApproverExecutable(path string) (ApproverIdentity, error) {
	identity := p.identity
	if identity.ExecutablePath == "" {
		identity.ExecutablePath = path
	}
	return identity, nil
}

func (l *recordingLauncher) Launch(_ context.Context, _ string, payload ApprovalRequestPayload) (ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, payload)
	if l.err != nil {
		return ExpectedApprover{}, l.err
	}
	return l.expected, nil
}

func (l *recordingLauncher) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}

func newBlockingLauncher() *blockingLauncher {
	return &blockingLauncher{
		started: make(chan struct{}),
	}
}

func (l *blockingLauncher) Launch(ctx context.Context, _ string, _ ApprovalRequestPayload) (ExpectedApprover, error) {
	close(l.started)
	<-ctx.Done()
	return ExpectedApprover{}, ctx.Err()
}

func (l *exitingLauncher) Launch(_ context.Context, _ string, _ ApprovalRequestPayload) (ExpectedApprover, error) {
	expected := l.expected
	expected.exited = l.exited
	return expected, nil
}

func (l *contextObservingLauncher) Launch(ctx context.Context, _ string, _ ApprovalRequestPayload) (ExpectedApprover, error) {
	go func() {
		<-ctx.Done()
		close(l.canceled)
	}()
	return l.expected, nil
}

func TestApprovalFixturesDecodeInGo(t *testing.T) {
	t.Parallel()

	requestData := readFixture(t, "approval_request.json")
	var approvalRequest ApprovalRequestPayload
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
	var decision ApprovalDecisionPayload
	if err := json.Unmarshal(decisionData, &decision); err != nil {
		t.Fatalf("decode approval decision fixture: %v", err)
	}
	if decision.Decision != "approve_reusable" || decision.ReusableUses == nil || *decision.ReusableUses != 3 {
		t.Fatalf("unexpected approval decision: %+v", decision)
	}
}

func TestSocketApproverLaunchesAndAcceptsExpectedPeerDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	req.ReusableUses = 2

	resultCh := make(chan ApprovalDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	waitForPending(t, approver)

	payload, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
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
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID:    "req_1",
		Nonce:        "nonce_1",
		Decision:     "approve_reusable",
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
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	resultCh := make(chan ApprovalDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	waitForPending(t, approver)

	payload, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	mismatchedUses := payload.ReusableUses + 1
	for _, decision := range []ApprovalDecisionPayload{
		{
			RequestID: "req_1",
			Nonce:     "nonce_1",
			Decision:  "approve_reusable",
		},
		{
			RequestID:    "req_1",
			Nonce:        "nonce_1",
			Decision:     "approve_reusable",
			ReusableUses: &mismatchedUses,
		},
	} {
		err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), decision)
		if !errors.Is(err, ErrMalformedEnvelope) {
			t.Fatalf("SubmitDecision reusable count mismatch error = %v, want malformed envelope", err)
		}
	}

	uses := payload.ReusableUses
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID:    "req_1",
		Nonce:        "nonce_1",
		Decision:     "approve_reusable",
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
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid()+1, exe)); !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("expected peer mismatch, got %v", err)
	}
	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "wrong",
		Decision:  "approve_once",
	})
	if !errors.Is(err, ErrStaleApproval) {
		t.Fatalf("expected stale approval error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "deny",
	})
	if err != nil {
		t.Fatalf("SubmitDecision deny returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, ErrApprovalDenied) {
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
		expected: ExpectedApprover{
			PID:               os.Getpid(),
			ExecutablePath:    exe,
			ExpectedTeamID:    "TEAMID",
			VerifySignature:   true,
			signatureVerifier: verifier,
		},
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(ctx, "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	_, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("expected approver peer mismatch, got %v", err)
	}
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
		expected: ExpectedApprover{
			PID:               os.Getpid(),
			ExecutablePath:    exe,
			ExpectedTeamID:    "TEAMID",
			VerifySignature:   true,
			signatureVerifier: verifier,
		},
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(ctx, "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	verifier.processTeamID = "OTHERTEAM"
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
	})
	if !errors.Is(err, ErrApproverPeerMismatch) {
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
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, func() time.Time { return now })
	first := approvalTestRequest(t, now.Add(time.Minute))
	expiredSecond := approvalTestRequest(t, now.Add(-time.Second))

	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", first)
		firstErr <- err
	}()
	waitForPending(t, approver)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_2", "nonce_2", expiredSecond)
		secondErr <- err
	}()

	payload, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe))
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	if payload.RequestID != "req_1" {
		t.Fatalf("FIFO displayed request %q first", payload.RequestID)
	}
	if err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
	}); err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}
	if err := <-firstErr; err != nil {
		t.Fatalf("first approval returned error: %v", err)
	}
	if err := <-secondErr; !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("second approval error = %v, want expired", err)
	}
	if launcher.Count() != 1 {
		t.Fatalf("expired queued request launched approver; launches=%d", launcher.Count())
	}
}

func TestSocketApproverExpiresActiveRequestWithoutDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(20*time.Millisecond))

	_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverFailsWhenExpectedApproverExitsBeforeFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	exited := make(chan error, 1)
	launcher := &exitingLauncher{
		expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		exited:   exited,
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	exited <- errors.New("exit status 64")
	close(exited)

	if err := receiveApprovalError(t, errCh, "ApproveExec did not observe early approver exit"); !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("ApproveExec error = %v, want launch failure", err)
	}
	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); !errors.Is(err, ErrNoPendingApproval) {
		t.Fatalf("FetchPending after early exit = %v, want no pending approval", err)
	}
}

func TestSocketApproverIgnoresExpectedApproverExitAfterFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	exited := make(chan error, 1)
	launcher := &exitingLauncher{
		expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		exited:   exited,
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	resultCh := make(chan ApprovalDecision, 1)
	errCh := make(chan error, 1)
	go func() {
		decision, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- decision
	}()
	waitForPending(t, approver)

	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	exited <- errors.New("exit status 64")
	close(exited)

	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
	})
	if err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
	}
	select {
	case decision := <-resultCh:
		if !decision.Approved {
			t.Fatalf("unexpected approval result: %+v", decision)
		}
	case err := <-errCh:
		t.Fatalf("ApproveExec returned error after fetch: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for approval result")
	}
}

func TestSocketApproverLaunchContextLivesUntilApprovalCompletes(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &contextObservingLauncher{
		expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe},
		canceled: make(chan struct{}),
	}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	select {
	case <-launcher.canceled:
		t.Fatal("launch context was canceled before approval completed")
	default:
	}

	if _, err := approver.FetchPending(context.Background(), peerInfoForTest(t, os.Getpid(), exe)); err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
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
		_, err := approver.ApproveExec(approveCtx, "req_1", "nonce_1", req)
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
		_, err := approver.ApproveExec(approveCtx, "req_1", "nonce_1", req)
		approveErr <- err
	}()
	receiveApprovalSignal(t, launcher.started, "approver launch did not start")

	decisionCtx, cancelDecision := context.WithCancel(context.Background())
	decisionErr := make(chan error, 1)
	go func() {
		decisionErr <- approver.SubmitDecision(
			decisionCtx,
			peerInfoForTest(t, os.Getpid(), exe),
			ApprovalDecisionPayload{
				RequestID: "req_1",
				Nonce:     "nonce_1",
				Decision:  "approve_once",
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

	if _, err := NewSocketApprover("", &recordingLauncher{}, time.Now); err == nil {
		t.Fatal("expected missing socket path error")
	}
	if _, err := NewSocketApprover("/tmp/agent-secret-test.sock", nil, time.Now); !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("expected launcher error, got %v", err)
	}
}

func TestSocketApproverRejectsInvalidDecision(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	req := approvalTestRequest(t, time.Now().Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "banana",
	})
	if !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("expected malformed decision error, got %v", err)
	}
	err = approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "timeout",
	})
	if err != nil {
		t.Fatalf("timeout decision returned error: %v", err)
	}
	if err := <-errCh; !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverTreatsExpiredApprovalAsTimeout(t *testing.T) {
	t.Parallel()

	if err := submitExpiredDecisionForTest(t, "approve_once"); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("ApproveExec error = %v, want expired", err)
	}
}

func TestSocketApproverPreservesExpiredDenial(t *testing.T) {
	t.Parallel()

	if err := submitExpiredDecisionForTest(t, "deny"); !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("ApproveExec error = %v, want denied", err)
	}
}

func submitExpiredDecisionForTest(t *testing.T, decision string) error {
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
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: os.Getpid(), ExecutablePath: exe}}
	approver := newSocketApproverForTest(t, launcher, nowFn)
	req := approvalTestRequest(t, now.Add(time.Minute))
	errCh := make(chan error, 1)
	go func() {
		_, err := approver.ApproveExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	waitForPending(t, approver)

	setNow(req.ExpiresAt)
	err := approver.SubmitDecision(context.Background(), peerInfoForTest(t, os.Getpid(), exe), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  decision,
	})
	if err != nil {
		t.Fatalf("expired %s decision returned error: %v", decision, err)
	}
	return <-errCh
}

func TestProcessApproverLauncherExecutablePath(t *testing.T) {
	t.Parallel()

	appPath := filepath.Join(t.TempDir(), "AgentSecretApprover.app")
	got, err := (ProcessApproverLauncher{AppPath: appPath}).executablePath()
	if err != nil {
		t.Fatalf("app executablePath returned error: %v", err)
	}
	want := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")
	if got != want {
		t.Fatalf("app executable path = %q, want %q", got, want)
	}

	binaryPath := filepath.Join(t.TempDir(), "agent-secret-approver")
	got, err = (ProcessApproverLauncher{AppPath: binaryPath}).executablePath()
	if err != nil {
		t.Fatalf("binary executablePath returned error: %v", err)
	}
	if got != binaryPath {
		t.Fatalf("binary executable path = %q, want %q", got, binaryPath)
	}
}

func TestProcessApproverLauncherPrefersUnifiedAppExecutable(t *testing.T) {
	t.Parallel()

	appPath := filepath.Join(t.TempDir(), "Agent Secret.app")
	unifiedExecutable := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")
	legacyExecutable := filepath.Join(appPath, "Contents", "MacOS", "agent-secret-approver")
	if err := os.MkdirAll(filepath.Dir(unifiedExecutable), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(legacyExecutable, []byte("test"), 0o755); err != nil { //nolint:gosec // G306: approver tests need runnable app executable fixtures.
		t.Fatalf("write legacy executable: %v", err)
	}
	if err := os.WriteFile(unifiedExecutable, []byte("test"), 0o755); err != nil { //nolint:gosec // G306: approver tests need runnable app executable fixtures.
		t.Fatalf("write unified executable: %v", err)
	}

	got, err := (ProcessApproverLauncher{AppPath: appPath}).executablePath()
	if err != nil {
		t.Fatalf("app executablePath returned error: %v", err)
	}
	if got != unifiedExecutable {
		t.Fatalf("app executable path = %q, want unified executable %q", got, unifiedExecutable)
	}
}

func TestApproverCandidatesForBundledExecutables(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	cliPath := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")
	daemonPath := filepath.Join(
		appPath,
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
		"Contents",
		"MacOS",
		"Agent Secret",
	)
	want := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")

	if !slices.Contains(approverCandidatesForExecutable(cliPath), want) {
		t.Fatalf("cli approver candidates missing top-level app executable")
	}
	if !slices.Contains(approverCandidatesForExecutable(daemonPath), want) {
		t.Fatalf("daemon approver candidates missing top-level app executable")
	}
}

func TestDefaultApproverPathUsesInstalledUnifiedApp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, "Applications", "Agent Secret.app", "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: default approver path tests need runnable app executable fixtures.
		t.Fatalf("write app executable: %v", err)
	}

	got, err := defaultApproverPath()
	if err != nil {
		t.Fatalf("defaultApproverPath returned error: %v", err)
	}
	if got != want {
		t.Fatalf("default approver path = %q, want installed app executable %q", got, want)
	}
}

func TestDefaultApproverPathIgnoresEnvironmentOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_APPROVER_PATH", filepath.Join(t.TempDir(), "PoisonApprover.app"))
	want := filepath.Join(home, "Applications", "Agent Secret.app", "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatalf("create app macos dir: %v", err)
	}
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: default approver path tests need runnable app executable fixtures.
		t.Fatalf("write app executable: %v", err)
	}

	got, err := defaultApproverPath()
	if err != nil {
		t.Fatalf("defaultApproverPath returned error: %v", err)
	}
	if got != want {
		t.Fatalf("default approver path = %q, want installed app executable %q", got, want)
	}
}

func TestProcessApproverLauncherLaunchesBinary(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.PID <= 0 {
		t.Fatalf("expected launched process pid, got %+v", expected)
	}
	if expected.ExecutablePath != helper {
		t.Fatalf("expected executable path = %q, want %q", expected.ExecutablePath, helper)
	}
}

func TestProcessApproverLauncherExposesEarlyProcessExit(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.exited == nil {
		t.Fatal("expected process exit monitor channel")
	}
	select {
	case err := <-expected.exited:
		if err == nil {
			t.Fatal("expected non-zero helper exit error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for helper process exit")
	}
}

func TestProcessApproverLauncherCarriesSignaturePolicyToExpectedPeer(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	expected, err := (ProcessApproverLauncher{
		AppPath: helper,
		IdentityPolicy: staticApproverIdentityPolicy{identity: ApproverIdentity{
			ExpectedTeamID:  "TEAMID",
			VerifySignature: true,
		}},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if err != nil {
		t.Fatalf("Launch returned error: %v", err)
	}
	if expected.ExpectedTeamID != "TEAMID" {
		t.Fatalf("ExpectedTeamID = %q, want TEAMID", expected.ExpectedTeamID)
	}
	if !expected.VerifySignature {
		t.Fatal("VerifySignature = false, want true")
	}
	if expected.signatureVerifier == nil {
		t.Fatal("signatureVerifier is nil")
	}
}

func TestProcessApproverLauncherHealthCheck(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nif [ \"$1\" = \"--health-check\" ]; then echo 'agent-secret-approver: ok'; exit 0; fi\nexit 64\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).CheckHealth(context.Background())
	if err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
}

func TestProcessApproverLauncherHealthCheckRejectsUnexpectedOutput(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "approver-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho nope\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	err := (ProcessApproverLauncher{
		AppPath:        helper,
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).CheckHealth(context.Background())
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("CheckHealth error = %v, want ErrApproverLaunchFailed", err)
	}
}

func TestProcessApproverLauncherRejectsBareBinaryByDefault(t *testing.T) {
	t.Parallel()

	helper := filepath.Join(t.TempDir(), "agent-secret-approver")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: launcher tests need runnable helper executables.
		t.Fatalf("write helper: %v", err)
	}

	_, err := (ProcessApproverLauncher{AppPath: helper}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func TestProcessApproverLauncherWrapsStartFailure(t *testing.T) {
	t.Parallel()

	_, err := (ProcessApproverLauncher{
		AppPath:        filepath.Join(t.TempDir(), "missing"),
		IdentityPolicy: allowApproverIdentityPolicy{},
	}).Launch(
		context.Background(),
		"/tmp/agent-secret-test.sock",
		ApprovalRequestPayload{},
	)
	if !errors.Is(err, ErrApproverLaunchFailed) {
		t.Fatalf("expected launch failure, got %v", err)
	}
}

func TestBundleApproverIdentityPolicyValidatesBundleMetadata(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	identity, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if err != nil {
		t.Fatalf("ValidateApproverExecutable returned error: %v", err)
	}
	wantExecutable, err := comparableApproverPath(executable)
	if err != nil {
		t.Fatalf("comparableApproverPath returned error: %v", err)
	}
	if identity.ExecutablePath != wantExecutable {
		t.Fatalf("identity executable = %q, want %q", identity.ExecutablePath, wantExecutable)
	}
	if identity.BundleID != DefaultApproverBundleID {
		t.Fatalf("identity bundle id = %q", identity.BundleID)
	}
}

func TestDefaultApproverIdentityMatchesBundleMetadata(t *testing.T) {
	t.Parallel()

	metadata := readBundleMetadata(t)
	if DefaultApproverBundleID != metadata["AGENT_SECRET_APP_BUNDLE_ID"] {
		t.Fatalf(
			"DefaultApproverBundleID = %q, want bundle metadata %q",
			DefaultApproverBundleID,
			metadata["AGENT_SECRET_APP_BUNDLE_ID"],
		)
	}
	if DefaultApproverExecutable != metadata["AGENT_SECRET_APP_EXECUTABLE"] {
		t.Fatalf(
			"DefaultApproverExecutable = %q, want bundle metadata %q",
			DefaultApproverExecutable,
			metadata["AGENT_SECRET_APP_EXECUTABLE"],
		)
	}
}

func TestDefaultApproverIdentityPolicyUsesBuildConfiguredTeamID(t *testing.T) {
	previous := defaultDeveloperIDTeamID
	defaultDeveloperIDTeamID = " B6L7QLWTZW "
	t.Cleanup(func() {
		defaultDeveloperIDTeamID = previous
	})

	policy := DefaultApproverIdentityPolicy()
	if policy.ExpectedTeamID != "B6L7QLWTZW" {
		t.Fatalf("ExpectedTeamID = %q, want configured Developer ID Team ID", policy.ExpectedTeamID)
	}
}

func TestBundleApproverIdentityPolicyRejectsMissingTeamIDWhenSignatureVerificationEnabled(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, DefaultApproverExecutable)
	_, err := (BundleApproverIdentityPolicy{VerifySignature: true}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected Developer ID Team ID is required") {
		t.Fatalf("error = %q, want missing Team ID context", err.Error())
	}
}

func TestApproverPeerValidationRejectsMissingTeamIDWhenSignatureVerificationEnabled(t *testing.T) {
	t.Parallel()

	err := validateApproverPeer(
		ExpectedApprover{
			PID:             os.Getpid(),
			ExecutablePath:  currentExecutable(t),
			VerifySignature: true,
		},
		peerInfoForTest(t, os.Getpid(), currentExecutable(t)),
	)
	if !errors.Is(err, ErrApproverPeerMismatch) {
		t.Fatalf("expected approver peer mismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "expected Developer ID Team ID is required") {
		t.Fatalf("error = %q, want missing Team ID context", err.Error())
	}
}

func TestApproverPeerValidationAllowsExplicitDevelopmentTeamIDSentinel(t *testing.T) {
	t.Parallel()

	err := validateApproverPeer(
		ExpectedApprover{
			PID:             os.Getpid(),
			ExecutablePath:  currentExecutable(t),
			ExpectedTeamID:  developmentExpectedTeamID,
			VerifySignature: true,
		},
		peerInfoForTest(t, os.Getpid(), currentExecutable(t)),
	)
	if err != nil {
		t.Fatalf("explicit development Team ID sentinel returned error: %v", err)
	}
}

func TestBundleApproverIdentityPolicyRejectsWrongBundleID(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), "com.example.fake", DefaultApproverExecutable)
	_, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
}

func TestBundleApproverIdentityPolicyRejectsWrongExecutableName(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, "Fake Approver")
	_, err := (BundleApproverIdentityPolicy{VerifySignature: false}).ValidateApproverExecutable(executable)
	if !errors.Is(err, ErrApproverIdentity) {
		t.Fatalf("expected approver identity error, got %v", err)
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Fatalf("error = %q, want executable context", err.Error())
	}
}

func newSocketApproverForTest(t *testing.T, launcher ApproverLauncher, now func() time.Time) *SocketApprover {
	t.Helper()
	approver, err := NewSocketApprover("/tmp/agent-secret-test.sock", launcher, now)
	if err != nil {
		t.Fatalf("NewSocketApprover returned error: %v", err)
	}
	return approver
}

func writeApproverBundle(t *testing.T, dir string, bundleID string, executableName string) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "AgentSecretApprover.app")
	macOSPath := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSPath, 0o750); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	executablePath := filepath.Join(macOSPath, executableName)
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: bundle identity tests need runnable app executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>` + bundleID + `</string>
  <key>CFBundleExecutable</key>
  <string>` + executableName + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(bundlePath, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}
	return executablePath
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
		Secrets:      []request.Secret{{Alias: "TOKEN", Ref: ref, Account: "Work"}},
		ReceivedAt:   expiresAt.Add(-request.DefaultExecTTL),
		ExpiresAt:    expiresAt,
		TTL:          request.DefaultExecTTL,
		DeliveryMode: request.DeliveryEnvExec,
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

func readBundleMetadata(t *testing.T) map[string]string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "scripts", "bundle-metadata.sh")
	//nolint:gosec // G304: test metadata path is derived from runtime.Caller within this repository.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle metadata: %v", err)
	}

	metadata := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		metadata[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return metadata
}

func waitForPending(t *testing.T, approver *SocketApprover) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		approver.mu.Lock()
		ready := approver.active != nil && approver.active.expectedReady
		approver.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for pending approval")
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
