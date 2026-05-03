package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/policy"
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
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
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

func TestServerRebasesExecRequestTimeToDaemonClock(t *testing.T) {
	t.Parallel()

	daemonNow := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	approver := &recordingApprover{
		decision: ApprovalDecision{Approved: true},
		seen:     make(chan request.ExecRequest, 1),
	}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequestAt(t, daemonNow.Add(24*time.Hour), []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	req.TTL = 10 * time.Minute
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}

	select {
	case got := <-approver.seen:
		if !got.ReceivedAt.Equal(daemonNow) {
			t.Fatalf("received_at = %s, want daemon clock %s", got.ReceivedAt, daemonNow)
		}
		if !got.ExpiresAt.Equal(daemonNow.Add(req.TTL)) {
			t.Fatalf("expires_at = %s, want daemon clock plus ttl %s", got.ExpiresAt, daemonNow.Add(req.TTL))
		}
	case <-time.After(time.Second):
		t.Fatal("approver did not receive exec request")
	}
}

func TestServerAllowsCommandCompletionAfterProtocolReadTimeout(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Validator:     allowPeerValidator{},
		ExecValidator: NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
		ReadTimeout:   20 * time.Millisecond,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if err := client.ReportStarted(context.Background(), "req_1", "nonce_1", 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	if err := client.ReportCompleted(context.Background(), "req_1", "nonce_1", 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error after protocol read timeout: %v", err)
	}
	got := auditEventTypes(aud.Events())
	if len(got) == 0 || got[len(got)-1] != audit.EventCommandCompleted {
		t.Fatalf("audit events = %v; last event should be %s", got, audit.EventCommandCompleted)
	}
}

func TestServerRejectsBadProtocolVersionAndNonceMismatch(t *testing.T) {
	t.Parallel()

	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey("op://Example/Item/token", "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	raw, err := Dial(context.Background(), testSocketPath(t))
	if err == nil {
		_ = raw.Close()
		t.Fatal("unexpectedly connected to unrelated test socket path")
	}

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
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

func TestServerRejectsOversizedProtocolFrame(t *testing.T) {
	t.Parallel()

	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, BrokerOptions{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     allowPeerValidator{},
		MaxFrameBytes: 96,
		ReadTimeout:   time.Second,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	frame := `{"version":1,"type":"daemon.status","payload":"` + strings.Repeat("x", 128) + `"}` + "\n"
	if _, err := conn.Write([]byte(frame)); err != nil {
		t.Fatalf("write oversized frame: %v", err)
	}

	var resp Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode oversized frame response: %v", err)
	}
	if resp.Type != TypeError {
		t.Fatalf("oversized frame response type = %s", resp.Type)
	}
	payload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode oversized frame error payload: %v", err)
	}
	if payload.Code != "frame_too_large" {
		t.Fatalf("oversized frame error code = %q, want frame_too_large", payload.Code)
	}
}

func TestServerClosesSlowPartialProtocolFrame(t *testing.T) {
	t.Parallel()

	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, BrokerOptions{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     allowPeerValidator{},
		ReadTimeout:   25 * time.Millisecond,
		MaxFrameBytes: 1024,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(`{"version":`)); err != nil {
		t.Fatalf("write partial frame: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection close for slow partial frame")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("server did not close slow partial frame before client deadline: %v", err)
	}
}

func TestServerValidatesExecPeerBeforeDecodingPayload(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, BrokerOptions{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: NewTrustedExecutableValidator([]string{writeExecutableAt(t, t.TempDir(), "agent-secret")}),
		MaxFrameBytes: 4096,
		ReadTimeout:   time.Second,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	env := Envelope{
		Version:   ProtocolVersion,
		Type:      TypeRequestExec,
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Payload:   json.RawMessage(`{"not":"a valid exec request"}`),
	}
	if err := json.NewEncoder(conn).Encode(env); err != nil {
		t.Fatalf("encode untrusted exec request: %v", err)
	}
	var resp Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode untrusted exec response: %v", err)
	}
	payload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode untrusted exec error payload: %v", err)
	}
	if payload.Code != "untrusted_client" {
		t.Fatalf("untrusted exec error code = %q, want untrusted_client", payload.Code)
	}
}

func TestServerClientDisconnectAfterPayloadAudits(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	defer cleanup()

	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
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

func TestServerFailedExecResponseWriteDoesNotConsumeReusableUse(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	req.ReusableUses = 1
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true, ReusableUses: 1}}
	aud := &callbackAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})

	var connMu sync.Mutex
	var firstConn *net.UnixConn
	var closeOnce sync.Once
	aud.onRecord = func(event audit.Event) {
		if event.Type != audit.EventCommandStarting || event.RequestID != "req_1" {
			return
		}
		closeOnce.Do(func() {
			connMu.Lock()
			conn := firstConn
			connMu.Unlock()
			if conn != nil {
				_ = conn.Close()
			}
		})
	}

	path, stop := startRawServerWithBroker(t, broker, nil, allowPeerValidator{})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	connMu.Lock()
	firstConn = conn
	connMu.Unlock()
	writeRawExecRequest(t, json.NewEncoder(conn), "req_1", "nonce_1", req)
	waitForAuditEvent(t, &aud.memoryAudit, audit.EventCommandStarting, "req_1")
	waitForInactiveRequest(t, broker, "req_1")

	secondConn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("second Dial returned error: %v", err)
	}
	secondClient := NewClient(secondConn)
	defer func() { _ = secondClient.Close() }()
	payload, err := secondClient.RequestExec(context.Background(), "req_2", "nonce_2", req)
	if err != nil {
		t.Fatalf("second RequestExec returned error: %v", err)
	}
	if payload.Env["TOKEN"] != "value" {
		t.Fatalf("second payload env = %+v", payload.Env)
	}
	if approver.calls != 1 {
		t.Fatalf("failed first response consumed reusable approval; approver calls = %d, want 1", approver.calls)
	}
	for _, event := range aud.Events() {
		if event.Type == audit.EventExecClientDisconnectedAfterPayload && event.RequestID == "req_1" {
			t.Fatalf("failed response write produced post-payload disconnect audit: %+v", event)
		}
	}
}

func TestServerRejectsExecPayloadWriteAfterDeliveryExpiry(t *testing.T) {
	t.Parallel()

	daemonNow := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	now := daemonNow
	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true, ReusableUses: 1}}
	broker := newTestBroker(t, BrokerOptions{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	var hookOnce sync.Once
	var approvalMu sync.Mutex
	var approvalID string
	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Validator:     allowPeerValidator{},
		ExecValidator: NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
		beforeExecResponseWrite: func() {
			hookOnce.Do(func() {
				broker.mu.Lock()
				if active := broker.active["req_1"]; active != nil {
					approvalMu.Lock()
					approvalID = active.approvalID
					approvalMu.Unlock()
				}
				broker.mu.Unlock()
				now = daemonNow.Add(request.DefaultExecTTL + time.Second)
			})
		},
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	defer func() { _ = client.Close() }()
	req := testExecRequestAt(t, daemonNow, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})

	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", req); !IsProtocolError(err, "request_expired") {
		t.Fatalf("RequestExec error = %v, want request_expired", err)
	}
	waitForInactiveRequest(t, broker, "req_1")
	approvalMu.Lock()
	gotApprovalID := approvalID
	approvalMu.Unlock()
	if gotApprovalID == "" {
		t.Fatal("server did not create a reusable approval before payload delivery")
	}
	if _, ok := cache.Get(gotApprovalID, ref, "Work"); ok {
		t.Fatal("expired reusable approval cache scope remained after failed payload delivery")
	}

	payload, err := client.RequestExec(context.Background(), "req_2", "nonce_2", req)
	if err != nil {
		t.Fatalf("second RequestExec returned error: %v", err)
	}
	if payload.Env["TOKEN"] != "value" {
		t.Fatalf("second payload env = %+v", payload.Env)
	}
	if approver.calls != 2 {
		t.Fatalf("expired payload write reused stale approval; approver calls = %d, want 2", approver.calls)
	}
}

func TestServerRejectsSecondExecOnSameSocketWithoutOrphaningFirst(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}}
	path, stop := startRawTestServer(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})

	writeRawExecRequest(t, encoder, "req_1", "nonce_1", req)
	first := readRawEnvelope(t, decoder)
	if first.Type != TypeOK {
		t.Fatalf("first exec response type = %q, want %q", first.Type, TypeOK)
	}

	writeRawExecRequest(t, encoder, "req_2", "nonce_2", req)
	second := readRawEnvelope(t, decoder)
	if second.Type != TypeError {
		t.Fatalf("second exec response type = %q, want %q", second.Type, TypeError)
	}
	errorPayload, err := DecodePayload[ErrorPayload](second)
	if err != nil {
		t.Fatalf("decode second exec error: %v", err)
	}
	if errorPayload.Code != "request_active" {
		t.Fatalf("second exec error code = %q, want request_active", errorPayload.Code)
	}

	_ = conn.Close()
	event := waitForAuditEvent(t, aud, audit.EventExecClientDisconnectedAfterPayload, "req_1")
	if event.RequestID != "req_1" {
		t.Fatalf("disconnect request id = %q, want req_1", event.RequestID)
	}
	if approver.calls != 1 {
		t.Fatalf("approver calls = %d, want 1", approver.calls)
	}
	if calls := resolver.Calls(); len(calls) != 1 {
		t.Fatalf("resolver calls = %v, want one call for first request", calls)
	}
	for _, event := range aud.Events() {
		if event.RequestID == "req_2" {
			t.Fatalf("second request produced audit event: %+v", event)
		}
	}
}

func TestServerClientDisconnectAfterStartAuditsIncompleteLifecycle(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): canarySecretValue}},
		Audit:    aud,
	})
	defer cleanup()

	if _, err := client.RequestExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if err := client.ReportStarted(context.Background(), "req_1", "nonce_1", 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	_ = client.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range aud.Events() {
			if event.Type == audit.EventExecClientDisconnectedAfterStart {
				if event.ChildPID == nil || *event.ChildPID != 4321 {
					t.Fatalf("disconnect child pid = %v, want 4321", event.ChildPID)
				}
				assertAuditEventsValueFree(t, aud.Events())
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("post-start disconnect audit was not recorded: %+v", aud.Events())
}

func TestServerDaemonStopTerminatesListener(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	aud := &memoryAudit{}
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    aud,
		}),
		nil,
		staticPeerValidator{info: peer},
		NewTrustedExecutableValidator([]string{exe}),
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
	if _, err := client.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	events := aud.Events()
	if len(events) != 1 || events[0].Type != audit.EventDaemonStop {
		t.Fatalf("stop audit events = %+v", events)
	}
	assertRequesterAudit(t, events[0], peer, "")
}

func TestServerRejectsExecOnExistingConnectionAfterStop(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	dir, err := os.MkdirTemp("/tmp", "agent-secret-test-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "d.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		Broker:        broker,
		Validator:     allowPeerValidator{},
		ExecValidator: NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	defer func() {
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
	}()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	server.Stop(context.Background())
	_, err = client.RequestExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref},
	}))
	if !IsProtocolError(err, "daemon_stopped") {
		t.Fatalf("RequestExec after stop error = %v, want daemon_stopped", err)
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver called after daemon stop: %v", calls)
	}
}

func TestServerRejectsUntrustedDaemonStopPeer(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	aud := &memoryAudit{}
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    aud,
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
	events := aud.Events()
	if len(events) != 1 || events[0].Type != audit.EventDaemonStop {
		t.Fatalf("stop audit events = %+v", events)
	}
	assertRequesterAudit(t, events[0], peer, "untrusted_client")
}

func TestServerApprovalProtocolOverSingleSocket(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	ref := "op://Example/Item/token"
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	broker := newTestBroker(t, BrokerOptions{
		Now:      time.Now,
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

func TestServerAllowsApprovalDecisionAfterProtocolReadTimeout(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	ref := "op://Example/Item/token"
	launcher := &recordingLauncher{expected: ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	broker := newTestBroker(t, BrokerOptions{
		Now:      time.Now,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Approvals:     approver,
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
		ReadTimeout:   20 * time.Millisecond,
	})
	defer stop()

	conn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial exec client returned error: %v", err)
	}
	client := NewClient(conn)
	defer func() { _ = client.Close() }()

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

	appConn, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial app client returned error: %v", err)
	}
	appClient := NewClient(appConn)
	defer func() { _ = appClient.Close() }()
	pending, err := appClient.FetchPendingApproval(context.Background())
	if err != nil {
		t.Fatalf("FetchPendingApproval returned error: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	if err := appClient.SubmitApprovalDecision(context.Background(), ApprovalDecisionPayload{
		RequestID: pending.RequestID,
		Nonce:     pending.Nonce,
		Decision:  "approve_once",
	}); err != nil {
		t.Fatalf("SubmitApprovalDecision returned error after protocol read timeout: %v", err)
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

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
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

func TestServerRejectsAccountlessExecRequestBeforeApproval(t *testing.T) {
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

func TestServerRejectsSessionSocketDeliveryBeforeApproval(t *testing.T) {
	t.Parallel()

	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	client, cleanup := startTestServer(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	req.DeliveryMode = request.DeliverySessionSocket
	req.MaxReads = 1
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
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
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

func TestServerRejectsRawSameUIDExecSocketClientBeforeApprovalOrFetch(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{
		values: map[string]string{"op://Example/Item/token": canarySecretValue},
	}
	aud := &memoryAudit{}
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, BrokerOptions{
			Approver: approver,
			Resolver: resolver,
			Audit:    aud,
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

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	payload, err := marshalPayload(req)
	if err != nil {
		t.Fatalf("marshal exec request: %v", err)
	}
	if err := json.NewEncoder(conn).Encode(Envelope{
		Version:   ProtocolVersion,
		Type:      TypeRequestExec,
		RequestID: "req_attacker",
		Nonce:     "nonce_attacker",
		Payload:   payload,
	}); err != nil {
		t.Fatalf("encode raw exec request: %v", err)
	}

	var resp Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode raw exec response: %v", err)
	}
	if resp.Type != TypeError {
		t.Fatalf("raw exec response type = %q, want %q", resp.Type, TypeError)
	}
	errorPayload, err := DecodePayload[ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode raw exec error payload: %v", err)
	}
	if errorPayload.Code != "untrusted_client" {
		t.Fatalf("raw exec error code = %q, want untrusted_client", errorPayload.Code)
	}
	if approver.calls != 0 {
		t.Fatalf("approver calls = %d, want 0", approver.calls)
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver calls = %v, want none", calls)
	}
	if events := aud.Events(); len(events) != 0 {
		t.Fatalf("audit events = %+v, want none before approval/fetch", events)
	}
	assertAuditEventsValueFree(t, aud.Events())
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
		{err: ErrRequestAlreadyActive, want: "request_active"},
		{err: ErrDaemonStopped, want: "daemon_stopped"},
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
	return startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Approvals:     approvals,
		Validator:     validator,
		ExecValidator: execValidator,
	})
}

func startRawServerWithOptions(t *testing.T, opts ServerOptions) (string, func()) {
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
	server, err := NewServer(opts)
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

func writeRawExecRequest(
	t *testing.T,
	encoder *json.Encoder,
	requestID string,
	nonce string,
	req request.ExecRequest,
) {
	t.Helper()

	env, err := NewEnvelope(TypeRequestExec, requestID, nonce, req)
	if err != nil {
		t.Fatalf("create exec envelope: %v", err)
	}
	if err := encoder.Encode(env); err != nil {
		t.Fatalf("encode exec envelope: %v", err)
	}
}

func readRawEnvelope(t *testing.T, decoder *json.Decoder) Envelope {
	t.Helper()

	var env Envelope
	if err := decoder.Decode(&env); err != nil {
		t.Fatalf("decode raw envelope: %v", err)
	}
	return env
}

func waitForAuditEvent(
	t *testing.T,
	aud *memoryAudit,
	eventType audit.EventType,
	requestID string,
) audit.Event {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, event := range aud.Events() {
			if event.Type == eventType && event.RequestID == requestID {
				return event
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit event %s for request %s was not recorded: %+v", eventType, requestID, aud.Events())
	return audit.Event{}
}

func waitForInactiveRequest(t *testing.T, broker *Broker, requestID string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		broker.mu.Lock()
		_, active := broker.active[requestID]
		broker.mu.Unlock()
		if !active {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("request %s remained active after response write failure", requestID)
}

func writeExecutableAt(t *testing.T, dir string, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon tests need runnable fixture executables.
		t.Fatalf("write executable: %v", err)
	}
	return path
}

func assertRequesterAudit(t *testing.T, event audit.Event, peer peercred.Info, wantErrorCode string) {
	t.Helper()

	if event.RequesterPID == nil || *event.RequesterPID != peer.PID {
		t.Fatalf("requester pid = %v, want %d", event.RequesterPID, peer.PID)
	}
	if event.RequesterUID == nil || *event.RequesterUID != peer.UID {
		t.Fatalf("requester uid = %v, want %d", event.RequesterUID, peer.UID)
	}
	if event.RequesterPath != peer.ExecutablePath {
		t.Fatalf("requester path = %q, want %q", event.RequesterPath, peer.ExecutablePath)
	}
	if event.ErrorCode != wantErrorCode {
		t.Fatalf("stop error code = %q, want %q", event.ErrorCode, wantErrorCode)
	}
}
