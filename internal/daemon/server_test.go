package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type allowPeerValidator struct{}

func (allowPeerValidator) Validate(_ *net.UnixConn) error {
	return nil
}

type staticPeerValidator struct {
	info peercred.Info
}

func (v staticPeerValidator) Validate(_ *net.UnixConn) error {
	return nil
}

func (v staticPeerValidator) Info(_ *net.UnixConn) (peercred.Info, error) {
	return v.info, nil
}

func TestServerExecProtocolLifecycle(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    aud,
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	payload, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if payload.Env["TOKEN"] != "value" {
		t.Fatalf("payload env = %+v", payload.Env)
	}
	if err := client.ReportStarted(context.Background(), "req_1", "nonce_1", 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := client.ReportCompleted(context.Background(), "req_1", "nonce_1", 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error: %v", err)
	}

	got := []audit.EventType{}
	for _, event := range aud.Events() {
		got = append(got, event.Type)
	}
	want := []audit.EventType{audit.EventCommandStarting, audit.EventCommandStarted, audit.EventCommandCompleted}
	if len(got) != len(want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit events = %v, want %v", got, want)
		}
	}
}

func TestServerRejectsBadProtocolVersionAndNonceMismatch(t *testing.T) {
	t.Parallel()

	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	raw, err := Dial(context.Background(), testSocketPath(t))
	if err == nil {
		_ = raw.Close()
		t.Fatal("unexpectedly connected to unrelated test socket path")
	}

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	err = client.ReportStarted(context.Background(), "req_1", "wrong", 1234)
	if !IsProtocolError(err, "invalid_nonce") {
		t.Fatalf("expected invalid nonce protocol error, got %v", err)
	}
}

func TestServerMalformedEnvelopeReturnsProtocolError(t *testing.T) {
	t.Parallel()

	path, stop := startRawTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	if err := encoder.Encode(Envelope{Version: 99, Type: TypeDaemonStatus}); err != nil {
		t.Fatalf("encode bad envelope: %v", err)
	}
	var resp Envelope
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode bad envelope response: %v", err)
	}
	if resp.Type != TypeError {
		t.Fatalf("bad envelope response type = %s", resp.Type)
	}
	payload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload.Code != "bad_envelope" {
		t.Fatalf("error code = %q, want bad_envelope", payload.Code)
	}
}

func TestServerClientDisconnectAfterPayloadAudits(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    aud,
	})
	defer cleanup()

	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	_ = client.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range aud.Events() {
			if event.Type == audit.EventExecClientDisconnectedAfterPayload {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("disconnect audit was not recorded: %+v", aud.Events())
}

func TestServerDaemonStopTerminatesListener(t *testing.T) {
	t.Parallel()

	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if _, err := client.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
}

func TestServerApprovalProtocolOverSingleSocket(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	ref := "op://Example/Item/token"
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
	})
	client, cleanup := startTestServerWithBroker(t, broker, approver, staticPeerValidator{info: peer})
	defer cleanup()

	execDone := make(chan ExecResponsePayload, 1)
	execErr := make(chan error, 1)
	go func() {
		payload, err := client.RequestExec(context.Background(), "req_1", "nonce_1", approvalTestRequest(t, time.Now().Add(time.Minute)))
		if err != nil {
			execErr <- err
			return
		}
		execDone <- payload
	}()
	waitForPendingOrExecError(t, approver, execErr)

	appConn, err := Dial(context.Background(), client.SocketPath)
	if err != nil {
		t.Fatalf("Dial app client returned error: %v", err)
	}
	appClient := NewClient(appConn)
	defer func() { _ = appClient.Close() }()
	pending, err := appClient.FetchPendingApproval(context.Background())
	if err != nil {
		t.Fatalf("FetchPendingApproval returned error: %v", err)
	}
	if pending.RequestID != "req_1" || pending.Nonce != "nonce_1" {
		t.Fatalf("unexpected pending approval payload: %+v", pending)
	}
	if err := appClient.SubmitApprovalDecision(context.Background(), ApprovalDecisionPayload{
		RequestID: pending.RequestID,
		Nonce:     pending.Nonce,
		Decision:  "approve_once",
	}); err != nil {
		t.Fatalf("SubmitApprovalDecision returned error: %v", err)
	}

	select {
	case payload := <-execDone:
		if payload.Env["TOKEN"] != "value" {
			t.Fatalf("exec payload = %+v", payload)
		}
	case err := <-execErr:
		t.Fatalf("RequestExec returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for exec response")
	}
}

func waitForPendingOrExecError(t *testing.T, approver *SocketApprover, execErr <-chan error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-execErr:
			t.Fatalf("RequestExec returned before pending approval: %v", err)
		default:
		}
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

func startTestServer(t *testing.T, opts BrokerOptions) (*Client, func()) {
	t.Helper()
	path, stop := startRawTestServer(t, opts)
	conn, err := Dial(context.Background(), path)
	if err != nil {
		stop()
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	return client, func() {
		_ = client.Close()
		stop()
	}
}

func startTestServerWithBroker(
	t *testing.T,
	broker *Broker,
	approvals ApprovalEndpoint,
	validator PeerValidator,
) (appTestClient, func()) {
	t.Helper()
	path, stop := startRawServerWithBroker(t, broker, approvals, validator)
	conn, err := Dial(context.Background(), path)
	if err != nil {
		stop()
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	return appTestClient{Client: client, SocketPath: path}, func() {
		_ = client.Close()
		stop()
	}
}

func startRawTestServer(t *testing.T, opts BrokerOptions) (string, func()) {
	t.Helper()
	broker := newTestBroker(t, opts)
	return startRawServerWithBroker(t, broker, nil, allowPeerValidator{})
}

type appTestClient struct {
	*Client

	SocketPath string
}

func startRawServerWithBroker(
	t *testing.T,
	broker *Broker,
	approvals ApprovalEndpoint,
	validator PeerValidator,
) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-test-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	server, err := NewServer(ServerOptions{Broker: broker, Approvals: approvals, Validator: validator})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	stop := func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("server returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server did not stop")
		}
		_ = os.Remove(path)
		_ = os.RemoveAll(dir)
	}
	return path, stop
}

func testSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "missing.sock")
}
