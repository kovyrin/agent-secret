package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type recordingLauncher struct {
	mu       sync.Mutex
	launched []ApprovalRequestPayload
	expected ExpectedApprover
	err      error
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
	uses := 3
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

func newSocketApproverForTest(t *testing.T, launcher ApproverLauncher, now func() time.Time) *SocketApprover {
	t.Helper()
	approver, err := NewSocketApprover("/tmp/agent-secret-test.sock", launcher, now)
	if err != nil {
		t.Fatalf("NewSocketApprover returned error: %v", err)
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
		CWD:                "/tmp/project",
		Secrets:            []request.Secret{{Alias: "TOKEN", Ref: ref}},
		ReceivedAt:         expiresAt.Add(-request.DefaultExecTTL),
		ExpiresAt:          expiresAt,
		TTL:                request.DefaultExecTTL,
		DeliveryMode:       request.DeliveryEnvExec,
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
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
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
