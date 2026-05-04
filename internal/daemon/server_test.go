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
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

type allowPeerValidator struct{}

func (allowPeerValidator) Info(conn *net.UnixConn) (peercred.Info, error) {
	return peercred.Inspect(conn)
}

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
	if v.err != nil {
		return peercred.Info{}, v.err
	}
	return v.info, nil
}

func trustedCurrentPeer(t *testing.T) (PeerValidator, peertrust.ExecValidator) {
	t.Helper()
	peer := peerInfoForTest(t, os.Getpid(), currentExecutable(t))
	return staticPeerValidator{info: peer}, peertrust.NewExecutableValidator([]string{peer.ExecutablePath})
}

func TestServerExecProtocolLifecycle(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	client, cleanup := startSocketPairTestServer(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	payload, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if payload.Env["TOKEN"] != "value" {
		t.Fatalf("payload env = %+v", payload.Env)
	}
	if err := client.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := client.ReportCompleted(context.Background(), testCorrelation("req_1", "nonce_1"), 0, ""); err != nil {
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

func TestServerStampsExecRequestTimeWithDaemonClock(t *testing.T) {
	t.Parallel()

	daemonNow := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	approver := &recordingApprover{
		decision: approval.Decision{Approved: true},
		seen:     make(chan request.ExecRequest, 1),
	}
	client, cleanup := startTestServer(t, daemonbroker.Options{
		Now:      func() time.Time { return daemonNow },
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequestAt(t, daemonNow.Add(24*time.Hour), []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	req.TTL = 10 * time.Minute
	req.ReceivedAt = time.Time{}
	req.ExpiresAt = time.Time{}
	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); err != nil {
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
	broker := newTestBroker(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	readTimeouts := make(chan time.Duration, 8)
	validator, execValidator := trustedCurrentPeer(t)
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:        broker,
		Validator:     validator,
		ExecValidator: execValidator,
		ReadTimeout:   time.Second,
		beforeRead: func(timeout time.Duration) {
			readTimeouts <- timeout
		},
	})
	defer stop()

	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if err := client.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	waitForReadTimeout(t, readTimeouts, 0)

	if err := client.ReportCompleted(context.Background(), testCorrelation("req_1", "nonce_1"), 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error after protocol read timeout: %v", err)
	}
	got := auditEventTypes(aud.Events())
	if len(got) == 0 || got[len(got)-1] != audit.EventCommandCompleted {
		t.Fatalf("audit events = %v; last event should be %s", got, audit.EventCommandCompleted)
	}
}

func TestServerRejectsLifecycleReportsFromDifferentConnection(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	path, stop := startRawTestServer(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	defer stop()

	ownerConn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("owner Dial returned error: %v", err)
	}
	owner := control.NewClient(ownerConn)
	defer func() { _ = owner.Close() }()

	otherConn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("other Dial returned error: %v", err)
	}
	other := control.NewClient(otherConn)
	defer func() { _ = other.Close() }()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	if _, err := owner.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if err := other.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 4321); !control.IsProtocolError(err, protocol.ErrorCodeInvalidNonce) {
		t.Fatalf("cross-connection ReportStarted error = %v, want invalid_nonce", err)
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarted) {
		t.Fatal("cross-connection ReportStarted produced command_started audit event")
	}

	if err := owner.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 4321); err != nil {
		t.Fatalf("owner ReportStarted returned error: %v", err)
	}
	if err := owner.ReportCompleted(context.Background(), testCorrelation("req_1", "nonce_1"), 0, ""); err != nil {
		t.Fatalf("owner ReportCompleted returned error: %v", err)
	}
}

func TestServerRejectsBadProtocolVersionAndNonceMismatch(t *testing.T) {
	t.Parallel()

	client, cleanup := startTestServer(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey("op://Example/Item/token", "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	raw, err := socket.Dial(context.Background(), testSocketPath(t))
	if err == nil {
		_ = raw.Close()
		t.Fatal("unexpectedly connected to unrelated test socket path")
	}

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	err = client.ReportStarted(context.Background(), testCorrelation("req_1", "wrong"), 1234)
	if !control.IsProtocolError(err, protocol.ErrorCodeInvalidNonce) {
		t.Fatalf("expected invalid nonce protocol error, got %v", err)
	}
}

func TestServerMalformedEnvelopeReturnsProtocolError(t *testing.T) {
	t.Parallel()

	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator: allowPeerValidator{},
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	if err := encoder.Encode(protocol.Envelope{Version: 99, Type: protocol.TypeDaemonStatus}); err != nil {
		t.Fatalf("encode bad envelope: %v", err)
	}
	var resp protocol.Envelope
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("decode bad envelope response: %v", err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("bad envelope response type = %s", resp.Type)
	}
	payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload.Code != "bad_envelope" {
		t.Fatalf("error code = %q, want bad_envelope", payload.Code)
	}
}

func TestServerRejectsOversizedProtocolFrame(t *testing.T) {
	t.Parallel()

	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, daemonbroker.Options{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     allowPeerValidator{},
		MaxFrameBytes: 96,
		ReadTimeout:   time.Second,
	})
	defer stop()

	defer func() { _ = conn.Close() }()

	frame := `{"version":1,"type":"daemon.status","payload":"` + strings.Repeat("x", 128) + `"}` + "\n"
	if _, err := conn.Write([]byte(frame)); err != nil {
		t.Fatalf("write oversized frame: %v", err)
	}

	var resp protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode oversized frame response: %v", err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("oversized frame response type = %s", resp.Type)
	}
	payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
	if err != nil {
		t.Fatalf("decode oversized frame error payload: %v", err)
	}
	if payload.Code != "frame_too_large" {
		t.Fatalf("oversized frame error code = %q, want frame_too_large", payload.Code)
	}
}

func TestServerClosesSlowPartialProtocolFrame(t *testing.T) {
	t.Parallel()

	expiredDeadlineClock := func() time.Time {
		return time.Now().Add(-2 * time.Second)
	}
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, daemonbroker.Options{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     allowPeerValidator{},
		ReadTimeout:   time.Second,
		MaxFrameBytes: 1024,
		now:           expiredDeadlineClock,
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(`{"version":`)); err != nil {
		t.Fatalf("write partial frame: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
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
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:        newTestBroker(t, daemonbroker.Options{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: peertrust.NewExecutableValidator([]string{writeClientExecutableAt(t, t.TempDir())}),
		MaxFrameBytes: 4096,
		ReadTimeout:   time.Second,
	})
	defer stop()

	defer func() { _ = conn.Close() }()

	env := protocol.Envelope{
		Version:   protocol.ProtocolVersion,
		Type:      protocol.TypeRequestExec,
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Payload:   json.RawMessage(`{"not":"a valid exec request"}`),
	}
	if err := json.NewEncoder(conn).Encode(env); err != nil {
		t.Fatalf("encode untrusted exec request: %v", err)
	}
	var resp protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode untrusted exec response: %v", err)
	}
	payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
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
	events, unsubscribe := aud.Subscribe()
	defer unsubscribe()
	client, cleanup := startTestServer(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})
	defer cleanup()

	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	_ = client.Close()

	_ = receiveAuditEvent(t, aud, events, audit.EventExecClientDisconnectedAfterPayload, "req_1")
}

func TestServerFailedExecResponseWriteDoesNotConsumeReusableUse(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	req.ReusableUses = 1
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 1}}
	aud := &callbackAudit{}
	events, unsubscribe := aud.Subscribe()
	defer unsubscribe()
	broker := newTestBroker(t, daemonbroker.Options{
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

	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	connMu.Lock()
	firstConn = conn
	connMu.Unlock()
	writeRawExecRequest(t, json.NewEncoder(conn), "req_1", "nonce_1", req)
	waitForAuditEvent(t, &aud.memoryAudit, events, audit.EventCommandStarting, "req_1")

	secondConn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("second Dial returned error: %v", err)
	}
	secondClient := control.NewClient(secondConn)
	defer func() { _ = secondClient.Close() }()
	payload, err := secondClient.RequestExec(context.Background(), testCorrelation("req_2", "nonce_2"), req)
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
	cache := newRecordingSecretCache()
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 1}}
	broker := newTestBroker(t, daemonbroker.Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	req := testExecRequestAt(t, daemonNow, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})
	req.ReusableUses = 1
	var hookOnce sync.Once
	validator, execValidator := trustedCurrentPeer(t)
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:        broker,
		Validator:     validator,
		ExecValidator: execValidator,
		beforeExecResponseWrite: func() {
			hookOnce.Do(func() {
				now = daemonNow.Add(request.DefaultExecTTL + time.Second)
			})
		},
	})
	defer stop()

	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); !control.IsProtocolError(err, protocol.ErrorCodeRequestExpired) {
		t.Fatalf("RequestExec error = %v, want request_expired", err)
	}
	if !cache.ScopeCleared() {
		t.Fatal("expired reusable approval cache scope was not cleared after failed payload delivery")
	}

	payload, err := client.RequestExec(context.Background(), testCorrelation("req_2", "nonce_2"), req)
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
	events, unsubscribe := aud.Subscribe()
	defer unsubscribe()
	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}}
	validator, execValidator := trustedCurrentPeer(t)
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: approver,
			Resolver: resolver,
			Audit:    aud,
		}),
		Validator:     validator,
		ExecValidator: execValidator,
	})
	defer stop()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}})

	writeRawExecRequest(t, encoder, "req_1", "nonce_1", req)
	first := readRawEnvelope(t, decoder)
	if first.Type != protocol.TypeOK {
		t.Fatalf("first exec response type = %q, want %q", first.Type, protocol.TypeOK)
	}

	writeRawExecRequest(t, encoder, "req_2", "nonce_2", req)
	second := readRawEnvelope(t, decoder)
	if second.Type != protocol.TypeError {
		t.Fatalf("second exec response type = %q, want %q", second.Type, protocol.TypeError)
	}
	errorPayload, err := protocol.DecodePayload[protocol.ErrorPayload](second)
	if err != nil {
		t.Fatalf("decode second exec error: %v", err)
	}
	if errorPayload.Code != "request_active" {
		t.Fatalf("second exec error code = %q, want request_active", errorPayload.Code)
	}

	_ = conn.Close()
	event := waitForAuditEvent(t, aud, events, audit.EventExecClientDisconnectedAfterPayload, "req_1")
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
	events, unsubscribe := aud.Subscribe()
	defer unsubscribe()
	client, cleanup := startTestServer(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): canarySecretValue}},
		Audit:    aud,
	})
	defer cleanup()

	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	})); err != nil {
		t.Fatalf("RequestExec returned error: %v", err)
	}
	if err := client.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 4321); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	_ = client.Close()

	event := receiveAuditEvent(t, aud, events, audit.EventExecClientDisconnectedAfterStart, "req_1")
	if event.ChildPID == nil || *event.ChildPID != 4321 {
		t.Fatalf("disconnect child pid = %v, want 4321", event.ChildPID)
	}
	assertAuditEventsValueFree(t, aud.Events())
}

func TestServerDaemonStopTerminatesListener(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	aud := &memoryAudit{}
	path, stop := startRawServerWithBrokerAndExecValidator(
		t,
		newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    aud,
		}),
		nil,
		staticPeerValidator{info: peer},
		peertrust.NewExecutableValidator([]string{exe}),
	)
	defer stop()

	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if _, err := client.RequestStop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	events := aud.Events()
	if len(events) != 1 || events[0].Type != audit.EventDaemonStop {
		t.Fatalf("stop audit events = %+v", events)
	}
	assertRequesterAudit(t, events[0], peer, "")
}

func TestServerOnePasswordStatusUsesInjectedCheck(t *testing.T) {
	t.Parallel()

	peer := peerInfoForTest(t, os.Getpid(), currentExecutable(t))
	checkErr := errors.New("desktop integration unavailable")
	checkCalls := 0
	server, err := NewServer(ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator:        staticPeerValidator{info: peer},
		ExecValidator:    peertrust.NewExecutableValidator([]string{peer.ExecutablePath}),
		OnePasswordCheck: func(context.Context) error { checkCalls++; return checkErr },
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	serverConn, clientConn := unixsocket.Pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConn(ctx, serverConn)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("server connection did not stop")
		}
	}()

	client := control.NewClient(clientConn)
	defer func() { _ = client.Close() }()
	err = client.CheckOnePassword(context.Background())
	if !control.IsProtocolError(err, protocol.ErrorCodeResolveFailed) {
		t.Fatalf("CheckOnePassword error = %v, want resolve_failed", err)
	}
	if checkCalls != 1 {
		t.Fatalf("one password check calls = %d, want 1", checkCalls)
	}
}

func TestServerRejectsExecOnExistingConnectionAfterStop(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	broker := newTestBroker(t, daemonbroker.Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	dir, err := os.MkdirTemp("/tmp", "agent-secret-test-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		Broker:        broker,
		Validator:     allowPeerValidator{},
		ExecValidator: peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
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

	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	server.Stop(context.Background())
	_, err = client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref},
	}))
	if !control.IsProtocolError(err, protocol.ErrorCodeDaemonStopped) {
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
		newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    aud,
		}),
		nil,
		staticPeerValidator{info: peer},
		peertrust.NewExecutableValidator([]string{writeClientExecutableAt(t, t.TempDir())}),
	)
	defer stop()

	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if _, err := client.RequestStop(context.Background()); !control.IsProtocolError(err, protocol.ErrorCodeUntrustedClient) {
		t.Fatalf("expected untrusted_client stop error, got %v", err)
	}
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("daemon stopped after rejected stop: %v", err)
	}
	events := aud.Events()
	if len(events) != 1 || events[0].Type != audit.EventDaemonStop {
		t.Fatalf("stop audit events = %+v", events)
	}
	assertRequesterAudit(t, events[0], peer, protocol.ErrorCodeUntrustedClient)
}

func TestServerApprovalProtocolOverSingleSocket(t *testing.T) {
	t.Parallel()

	exe := currentExecutable(t)
	peer := peerInfoForTest(t, os.Getpid(), exe)
	ref := "op://Example/Item/token"
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	broker := newTestBroker(t, daemonbroker.Options{
		Now:      time.Now,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	client, cleanup := startTestServerWithBroker(t, broker, approver, staticPeerValidator{info: peer})
	defer cleanup()

	execDone := make(chan protocol.ExecResponsePayload, 1)
	execErr := make(chan error, 1)
	go func() {
		payload, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), approvalTestRequest(t, time.Now().Add(time.Minute)))
		if err != nil {
			execErr <- err
			return
		}
		execDone <- payload
	}()
	appConn, err := socket.Dial(context.Background(), client.SocketPath)
	if err != nil {
		t.Fatalf("Dial app client returned error: %v", err)
	}
	appClient := newApprovalSocketTestClient(appConn)
	defer func() { _ = appClient.Close() }()
	pending := fetchPendingApprovalOrExecError(t, launcher, 1, appClient, execErr)
	if pending.RequestID != "req_1" || pending.Nonce != "nonce_1" {
		t.Fatalf("unexpected pending approval payload: %+v", pending)
	}
	if err := appClient.SubmitDecision(context.Background(), approval.ApprovalDecisionPayload{
		RequestID: pending.RequestID,
		Nonce:     pending.Nonce,
		Decision:  approval.ApprovalDecisionApproveOnce,
	}); err != nil {
		t.Fatalf("SubmitDecision returned error: %v", err)
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
	launcher := &recordingLauncher{expected: approval.ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath}}
	approver := newSocketApproverForTest(t, launcher, time.Now)
	broker := newTestBroker(t, daemonbroker.Options{
		Now:      time.Now,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	readTimeouts := make(chan time.Duration, 8)
	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Approvals:     approver,
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
		ReadTimeout:   time.Second,
		beforeRead: func(timeout time.Duration) {
			readTimeouts <- timeout
		},
	})
	defer stop()

	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial exec client returned error: %v", err)
	}
	client := control.NewClient(conn)
	defer func() { _ = client.Close() }()

	execDone := make(chan protocol.ExecResponsePayload, 1)
	execErr := make(chan error, 1)
	go func() {
		payload, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), approvalTestRequest(t, time.Now().Add(time.Minute)))
		if err != nil {
			execErr <- err
			return
		}
		execDone <- payload
	}()
	appConn, err := socket.Dial(context.Background(), path)
	if err != nil {
		t.Fatalf("Dial app client returned error: %v", err)
	}
	appClient := newApprovalSocketTestClient(appConn)
	defer func() { _ = appClient.Close() }()
	pending := fetchPendingApprovalOrExecError(t, launcher, 1, appClient, execErr)
	waitForReadTimeoutLongerThan(t, readTimeouts, time.Second)

	if err := appClient.SubmitDecision(context.Background(), approval.ApprovalDecisionPayload{
		RequestID: pending.RequestID,
		Nonce:     pending.Nonce,
		Decision:  approval.ApprovalDecisionApproveOnce,
	}); err != nil {
		t.Fatalf("SubmitDecision returned error after protocol read timeout: %v", err)
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

	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator:     allowPeerValidator{},
		ExecValidator: peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
	})
	defer stop()

	client := newApprovalSocketTestClient(conn)
	defer func() { _ = client.Close() }()

	_, err := client.FetchPending(context.Background())
	if !control.IsProtocolError(err, protocol.ErrorCodeApprovalUnavailable) {
		t.Fatalf("expected approval unavailable protocol error, got %v", err)
	}
	if err := client.SubmitDecision(context.Background(), approval.ApprovalDecisionPayload{
		RequestID: "req_1",
		Nonce:     "nonce_1",
		Decision:  approval.ApprovalDecisionApproveOnce,
	}); !control.IsProtocolError(err, protocol.ErrorCodeApprovalUnavailable) {
		t.Fatalf("expected approval unavailable decision error, got %v", err)
	}
}

func TestServerReportsBadMessagePayloadsAndTypes(t *testing.T) {
	t.Parallel()

	validator, execValidator := trustedCurrentPeer(t)
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator:     validator,
		ExecValidator: execValidator,
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	tests := []struct {
		env      protocol.Envelope
		wantCode string
	}{
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeRequestExec, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_request",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandStarted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "invalid_nonce",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandCompleted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "invalid_nonce",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: "banana", RequestID: "req_1", Nonce: "nonce_1"},
			wantCode: "bad_type",
		},
	}
	for _, tt := range tests {
		if err := encoder.Encode(tt.env); err != nil {
			t.Fatalf("encode %s: %v", tt.env.Type, err)
		}
		var resp protocol.Envelope
		if err := decoder.Decode(&resp); err != nil {
			t.Fatalf("decode response for %s: %v", tt.env.Type, err)
		}
		payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
		if err != nil {
			t.Fatalf("decode error payload for %s: %v", tt.env.Type, err)
		}
		if string(payload.Code) != tt.wantCode {
			t.Fatalf("%s code = %q, want %q", tt.env.Type, payload.Code, tt.wantCode)
		}
	}
}

func TestServerReportsBadLifecyclePayloadsForActiveRequest(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	validator, execValidator := trustedCurrentPeer(t)
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator:     validator,
		ExecValidator: execValidator,
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	writeRawExecRequest(t, encoder, "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref, Account: "Work"},
	}))
	if resp := readRawEnvelope(t, decoder); resp.Type != protocol.TypeOK {
		t.Fatalf("exec response type = %q, want %q", resp.Type, protocol.TypeOK)
	}

	tests := []struct {
		env      protocol.Envelope
		wantCode string
	}{
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandStarted, RequestID: "req_1", Nonce: "nonce_1"},
			wantCode: "bad_command_started",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandStarted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`{}`)},
			wantCode: "bad_command_started",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandStarted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_command_started",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandCompleted, RequestID: "req_1", Nonce: "nonce_1"},
			wantCode: "bad_command_completed",
		},
		{
			env:      protocol.Envelope{Version: protocol.ProtocolVersion, Type: protocol.TypeCommandCompleted, RequestID: "req_1", Nonce: "nonce_1", Payload: json.RawMessage(`[]`)},
			wantCode: "bad_command_completed",
		},
	}
	for _, tt := range tests {
		if err := encoder.Encode(tt.env); err != nil {
			t.Fatalf("encode %s: %v", tt.env.Type, err)
		}
		resp := readRawEnvelope(t, decoder)
		payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
		if err != nil {
			t.Fatalf("decode error payload for %s: %v", tt.env.Type, err)
		}
		if string(payload.Code) != tt.wantCode {
			t.Fatalf("%s code = %q, want %q", tt.env.Type, payload.Code, tt.wantCode)
		}
	}
}

func TestServerRejectsMalformedExecRequestBeforeApproval(t *testing.T) {
	t.Parallel()

	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	client, cleanup := startTestServer(t, daemonbroker.Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	req.Reason = "  fabricated metadata  "
	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); !control.IsProtocolError(err, protocol.ErrorCodeBadRequest) {
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

	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	client, cleanup := startTestServer(t, daemonbroker.Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	defer cleanup()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); !control.IsProtocolError(err, protocol.ErrorCodeBadRequest) {
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
	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: approver,
			Resolver: resolver,
			Audit:    &memoryAudit{},
		}),
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: peertrust.NewExecutableValidator([]string{writeClientExecutableAt(t, t.TempDir())}),
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	client := control.NewClient(conn)
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	if _, err := client.RequestExec(context.Background(), testCorrelation("req_1", "nonce_1"), req); !control.IsProtocolError(err, protocol.ErrorCodeUntrustedClient) {
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
	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{
		values: map[string]string{"op://Example/Item/token": canarySecretValue},
	}
	aud := &memoryAudit{}
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: approver,
			Resolver: resolver,
			Audit:    aud,
		}),
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: peertrust.NewExecutableValidator([]string{writeClientExecutableAt(t, t.TempDir())}),
	})
	defer stop()

	defer func() { _ = conn.Close() }()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"}})
	env, err := protocol.NewEnvelope(protocol.TypeRequestExec, testCorrelation("req_attacker", "nonce_attacker"), req)
	if err != nil {
		t.Fatalf("marshal exec request: %v", err)
	}
	if err := json.NewEncoder(conn).Encode(env); err != nil {
		t.Fatalf("encode raw exec request: %v", err)
	}

	var resp protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode raw exec response: %v", err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("raw exec response type = %q, want %q", resp.Type, protocol.TypeError)
	}
	errorPayload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
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
		expected: approval.ExpectedApprover{PID: peer.PID, ExecutablePath: peer.ExecutablePath},
	}, time.Now)
	broker := newTestBroker(t, daemonbroker.Options{
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &memoryAudit{},
	})
	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker:      broker,
		Approvals:   approver,
		Validator:   staticPeerValidator{info: peer},
		ReadTimeout: time.Second,
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	for _, payload := range []json.RawMessage{nil, json.RawMessage(`[]`)} {
		if err := encoder.Encode(protocol.Envelope{
			Version:   protocol.ProtocolVersion,
			Type:      protocol.TypeApprovalDecision,
			RequestID: "req_1",
			Nonce:     "nonce_1",
			Payload:   payload,
		}); err != nil {
			t.Fatalf("encode bad approval decision: %v", err)
		}
		resp := readRawEnvelope(t, decoder)
		errorPayload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
		if err != nil {
			t.Fatalf("decode error payload: %v", err)
		}
		if errorPayload.Code != "bad_approval_decision" {
			t.Fatalf("bad approval decision code = %q", errorPayload.Code)
		}
	}
}

func TestServerRejectsPeerBeforeDecodingRequest(t *testing.T) {
	t.Parallel()

	conn, stop := startRawServerConnWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator: staticPeerValidator{err: peercred.ErrPolicyMismatch},
	})
	defer stop()

	defer func() { _ = conn.Close() }()
	var resp protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode peer rejection: %v", err)
	}
	if resp.Type != protocol.TypeError {
		t.Fatalf("peer rejection response type = %s", resp.Type)
	}
	payload, err := protocol.DecodePayload[protocol.ErrorPayload](resp)
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
		want protocol.ErrorCode
	}{
		{err: approval.ErrApprovalDenied, want: protocol.ErrorCodeApprovalDenied},
		{err: daemonbroker.ErrAuditRequired, want: protocol.ErrorCodeAuditFailed},
		{err: protocol.ErrInvalidNonce, want: protocol.ErrorCodeInvalidNonce},
		{err: approval.ErrApproverPeerMismatch, want: protocol.ErrorCodeApproverPeerMismatch},
		{err: approval.ErrApproverIdentity, want: protocol.ErrorCodeApproverIdentityMismatch},
		{err: approval.ErrNoPendingApproval, want: protocol.ErrorCodeNoPendingApproval},
		{err: ErrRequestAlreadyActive, want: protocol.ErrorCodeRequestActive},
		{err: daemonbroker.ErrDaemonStopped, want: protocol.ErrorCodeDaemonStopped},
		{err: approval.ErrRequestExpired, want: protocol.ErrorCodeRequestExpired},
		{err: approval.ErrStaleApproval, want: protocol.ErrorCodeStaleApproval},
		{err: peertrust.ErrUntrustedClient, want: protocol.ErrorCodeUntrustedClient},
		{err: context.Canceled, want: protocol.ErrorCodeContextCanceled},
		{err: context.DeadlineExceeded, want: protocol.ErrorCodeContextDeadlineExceeded},
		{err: daemonbroker.ErrSecretResolveFailed, want: protocol.ErrorCodeResolveFailed},
		{err: errors.New("other"), want: protocol.ErrorCodeRequestFailed},
	}
	for _, tt := range tests {
		if got := codeForError(tt.err); got != tt.want {
			t.Fatalf("codeForError(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func fetchPendingApprovalOrExecError(
	t *testing.T,
	launcher launchWaiter,
	launchCount int,
	client *approvalSocketTestClient,
	execErr <-chan error,
) approval.ApprovalRequestPayload {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := launcher.waitForLaunch(ctx, launchCount); err != nil {
		select {
		case execErr := <-execErr:
			t.Fatalf("RequestExec returned before pending approval: %v", execErr)
		default:
			t.Fatalf("approver launch %d was not observed: %v", launchCount, err)
		}
	}
	pending, err := client.FetchPending(ctx)
	if err != nil {
		t.Fatalf("FetchPending returned error: %v", err)
	}
	return pending
}

func startTestServer(t *testing.T, opts daemonbroker.Options) (*control.Client, func()) {
	t.Helper()
	return startSocketPairTestServer(t, opts)
}

func startSocketPairTestServer(t *testing.T, opts daemonbroker.Options) (*control.Client, func()) {
	t.Helper()

	broker := newTestBroker(t, opts)
	peer := peerInfoForTest(t, os.Getpid(), currentExecutable(t))
	server, err := NewServer(ServerOptions{
		Broker:        broker,
		Validator:     staticPeerValidator{info: peer},
		ExecValidator: peertrust.NewExecutableValidator([]string{peer.ExecutablePath}),
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	serverConn, clientConn := unixsocket.Pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConn(ctx, serverConn)
	}()

	client := control.NewClient(clientConn)
	return client, func() {
		_ = client.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("socket-pair server connection did not stop")
		}
	}
}

func startTestServerWithBroker(
	t *testing.T,
	broker *daemonbroker.Broker,
	approvals approval.ApprovalEndpoint,
	validator PeerValidator,
) (appTestClient, func()) {
	t.Helper()
	path, stop := startRawServerWithBroker(t, broker, approvals, validator)
	conn, err := socket.Dial(context.Background(), path)
	if err != nil {
		stop()
		t.Fatalf("Dial returned error: %v", err)
	}
	client := control.NewClient(conn)
	return appTestClient{Client: client, SocketPath: path}, func() {
		_ = client.Close()
		stop()
	}
}

func startRawTestServer(t *testing.T, opts daemonbroker.Options) (string, func()) {
	t.Helper()
	broker := newTestBroker(t, opts)
	return startRawServerWithBroker(t, broker, nil, allowPeerValidator{})
}

type appTestClient struct {
	*control.Client

	SocketPath string
}

func startRawServerWithBroker(
	t *testing.T,
	broker *daemonbroker.Broker,
	approvals approval.ApprovalEndpoint,
	validator PeerValidator,
) (string, func()) {
	t.Helper()
	return startRawServerWithBrokerAndExecValidator(
		t,
		broker,
		approvals,
		validator,
		peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
	)
}

func startRawServerWithBrokerAndExecValidator(
	t *testing.T,
	broker *daemonbroker.Broker,
	approvals approval.ApprovalEndpoint,
	validator PeerValidator,
	execValidator peertrust.ExecValidator,
) (string, func()) {
	t.Helper()
	return startRawServerWithOptions(t, ServerOptions{
		Broker:        broker,
		Approvals:     approvals,
		Validator:     validator,
		ExecValidator: execValidator,
	})
}

func startRawServerConnWithOptions(t *testing.T, opts ServerOptions) (*net.UnixConn, func()) {
	t.Helper()
	server, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	serverConn, clientConn := unixsocket.Pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConn(ctx, serverConn)
	}()

	return clientConn, func() {
		_ = clientConn.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("socket-pair server connection did not stop")
		}
	}
}

func startRawServerWithOptions(t *testing.T, opts ServerOptions) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-test-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
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

	env, err := protocol.NewEnvelope(protocol.TypeRequestExec, testCorrelation(requestID, nonce), req)
	if err != nil {
		t.Fatalf("create exec envelope: %v", err)
	}
	if err := encoder.Encode(env); err != nil {
		t.Fatalf("encode exec envelope: %v", err)
	}
}

func readRawEnvelope(t *testing.T, decoder *json.Decoder) protocol.Envelope {
	t.Helper()

	var env protocol.Envelope
	if err := decoder.Decode(&env); err != nil {
		t.Fatalf("decode raw envelope: %v", err)
	}
	return env
}

func waitForAuditEvent(
	t *testing.T,
	aud *memoryAudit,
	events <-chan audit.Event,
	eventType audit.EventType,
	requestID string,
) audit.Event {
	t.Helper()

	for _, event := range aud.Events() {
		if event.Type == eventType && event.RequestID == requestID {
			return event
		}
	}
	return receiveAuditEvent(t, aud, events, eventType, requestID)
}

func receiveAuditEvent(
	t *testing.T,
	aud *memoryAudit,
	events <-chan audit.Event,
	eventType audit.EventType,
	requestID string,
) audit.Event {
	t.Helper()

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case event := <-events:
			if event.Type == eventType && event.RequestID == requestID {
				return event
			}
		case <-timeout.C:
			t.Fatalf("audit event %s for request %s was not recorded: %+v", eventType, requestID, aud.Events())
			return audit.Event{}
		}
	}
}

func waitForReadTimeout(t *testing.T, timeouts <-chan time.Duration, want time.Duration) {
	t.Helper()

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case got := <-timeouts:
			if got == want {
				return
			}
		case <-timeout.C:
			t.Fatalf("read timeout %s was not observed", want)
		}
	}
}

func waitForReadTimeoutLongerThan(t *testing.T, timeouts <-chan time.Duration, floor time.Duration) {
	t.Helper()

	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case got := <-timeouts:
			if got > floor {
				return
			}
		case <-timeout.C:
			t.Fatalf("read timeout longer than %s was not observed", floor)
		}
	}
}

func writeClientExecutableAt(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "agent-secret")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon tests need runnable fixture executables.
		t.Fatalf("write executable: %v", err)
	}
	return path
}

type recordingSecretCache struct {
	mu       sync.Mutex
	delegate *secretcache.SecretCache
	cleared  bool
}

func newRecordingSecretCache() *recordingSecretCache {
	return &recordingSecretCache{delegate: secretcache.NewSecretCache()}
}

func (c *recordingSecretCache) Put(key secretcache.CacheKey, value string) error {
	return c.delegate.Put(key, value)
}

func (c *recordingSecretCache) Get(key secretcache.CacheKey) (string, bool) {
	return c.delegate.Get(key)
}

func (c *recordingSecretCache) ClearScope(scopeID string) {
	c.mu.Lock()
	c.cleared = true
	c.mu.Unlock()
	c.delegate.ClearScope(scopeID)
}

func (c *recordingSecretCache) Clear() {
	c.delegate.Clear()
}

func (c *recordingSecretCache) ScopeCleared() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cleared
}

func assertRequesterAudit(t *testing.T, event audit.Event, peer peercred.Info, wantErrorCode protocol.ErrorCode) {
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
	if event.ErrorCode != audit.ErrorCode(wantErrorCode) {
		t.Fatalf("stop error code = %q, want %q", event.ErrorCode, wantErrorCode)
	}
}
