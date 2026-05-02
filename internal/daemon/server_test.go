package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
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
	err  error
}

func (v staticPeerValidator) Validate(_ *net.UnixConn) error {
	return v.err
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

	got := auditEventTypes(aud.Events())
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventCommandStarting,
		audit.EventCommandStarted,
		audit.EventCommandCompleted,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
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

func TestServerRejectsUntrustedDaemonStopPeer(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		nil,
		staticPeerValidator{info: peer},
		NewTrustedExecutableValidator([]string{writeExecutableAt(t, t.TempDir(), "agent-secret")}),
	)
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if _, err := client.Stop(context.Background()); !IsProtocolError(err, "untrusted_client") {
		t.Fatalf("expected untrusted_client stop error, got %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("daemon stopped after rejected stop: %v", err)
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
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
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

func TestServerReportsApprovalUnavailable(t *testing.T) {
	t.Parallel()

	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	_, err := client.FetchPendingApproval(context.Background())
	if !IsProtocolError(err, "approval_unavailable") {
		t.Fatalf("expected approval unavailable protocol error, got %v", err)
	}
	if err := client.SubmitApprovalDecision(context.Background(), ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  "approve_once",
	}); !IsProtocolError(err, "approval_unavailable") {
		t.Fatalf("expected approval unavailable decision error, got %v", err)
	}
}

func TestServerReportsBadMessagePayloadsAndTypes(t *testing.T) {
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

	tests := []struct {
		env      Envelope
		wantCode string
	}{
		{
			env:      Envelope{Version: ProtocolVersion, Type: TypeRequestExec, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_request",
		},
		{
			env:      Envelope{Version: ProtocolVersion, Type: TypeCommandStarted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_command_started",
		},
		{
			env:      Envelope{Version: ProtocolVersion, Type: TypeCommandCompleted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_command_completed",
		},
		{
			env:      Envelope{Version: ProtocolVersion, Type: "banana", RequestID: "req_1", Nonce: "nonce_1"},
			wantCode: "bad_type",
		},
	}
	for _, tt := range tests {
		if err := encoder.Encode(tt.env); err != nil {
			t.Fatalf("encode %s: %v", tt.env.Type, err)
		}
		var resp Envelope
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("decode response for %s: %v", tt.env.Type, err)
		}
		payload, err := DecodePayload[ErrorPayload](resp)
		if err != nil {
			t.Fatalf("decode error payload for %s: %v", tt.env.Type, err)
		}
		if payload.Code != tt.wantCode {
			t.Fatalf("%s code = %q, want %q", tt.env.Type, payload.Code, tt.wantCode)
		}
	}
}

func TestServerRejectsMalformedExecRequestBeforeApproval(t *testing.T) {
	t.Parallel()

	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	req.Reason = "  fabricated metadata  "
	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req); !IsProtocolError(err, "bad_request") {
		t.Fatalf("expected bad_request protocol error, got %v", err)
	}
	if approver.calls != 0 {
		t.Fatalf("approver calls = %d, want 0", approver.calls)
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver calls = %v, want none", calls)
	}
}

func TestServerRejectsUntrustedExecPeerBeforeSecretPayload(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: approver,
			Resolver: resolver,
			Audit:    &memoryAudit{},
		}),
		nil,
		staticPeerValidator{info: peer},
		NewTrustedExecutableValidator([]string{writeExecutableAt(t, t.TempDir(), "agent-secret")}),
	)
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := NewClient(conn)
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req); !IsProtocolError(err, "untrusted_client") {
		t.Fatalf("expected untrusted_client protocol error, got %v", err)
	}
	if approver.calls != 0 {
		t.Fatalf("approver calls = %d, want 0", approver.calls)
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver calls = %v, want none", calls)
	}
}

func TestServerReportsBadApprovalDecisionPayload(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	approver := newSocketApproverForTest(t, &recordingLauncher{
		expected: ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath},
	}, time.Now)
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	path, stop := startRawServerWithBroker(t, broker, approver, staticPeerValidator{info: peer})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(Envelope{
		Version:   ProtocolVersion,
		Type:      TypeApprovalDecision,
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Payload:   json.RawMessage(`[]`),
	}); err != nil {
		t.Fatalf("encode bad approval decision: %v", err)
	}
	var resp Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode bad approval decision response: %v", err)
	}
	payload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload.Code != "bad_approval_decision" {
		t.Fatalf("bad approval decision code = %q", payload.Code)
	}
}

func TestServerRejectsPeerBeforeDecodingRequest(t *testing.T) {
	t.Parallel()

	path, stop := startRawServerWithBroker(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		nil,
		staticPeerValidator{err: peercred.ErrPolicyMismatch},
	)
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	var resp Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode peer rejection: %v", err)
	}
	if resp.Type != TypeError {
		t.Fatalf("peer rejection response type = %s", resp.Type)
	}
	payload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode peer rejection payload: %v", err)
	}
	if payload.Code != "peer_rejected" {
		t.Fatalf("peer rejection code = %q", payload.Code)
	}
}

func TestCodeForErrorMapsProtocolFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		want string
	}{
		{err: ErrApprovalDenied, want: "approval_denied"},
		{err: ErrAuditRequired, want: "audit_failed"},
		{err: ErrInvalidNonce, want: "invalid_nonce"},
		{err: ErrApproverPeerMismatch, want: "approver_peer_mismatch"},
		{err: ErrApproverIdentity, want: "approver_identity_mismatch"},
		{err: ErrNoPendingApproval, want: "no_pending_approval"},
		{err: ErrRequestExpired, want: "request_expired"},
		{err: ErrStaleApproval, want: "stale_approval"},
		{err: ErrUntrustedClient, want: "untrusted_client"},
		{err: errors.New("other"), want: "request_failed"},
	}
	for _, tt := range tests {
		if got := codeForError(tt.err); got != tt.want {
			t.Fatalf("codeForError(%v) = %q, want %q", tt.err, got, tt.want)
		}
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
	return startRawServerWithBrokerAndExecValidator(
		t,
		broker,
		approvals,
		validator,
		NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
	)
}

func startRawServerWithBrokerAndExecValidator(
	t *testing.T,
	broker *Broker,
	approvals ApprovalEndpoint,
	validator PeerValidator,
	execValidator ExecPeerValidator,
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
	server, err := NewServer(ServerOptions{
		Broker:        broker,
		Approvals:     approvals,
		Validator:     validator,
		ExecValidator: execValidator,
	})
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

func writeExecutableAt(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	return path
}
