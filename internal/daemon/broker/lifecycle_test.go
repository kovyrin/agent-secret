package broker

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

func TestBrokerStopCancelsPendingApproval(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &blockingApprover{started: make(chan struct{}), canceled: make(chan struct{})}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	errCh := make(chan error, 1)
	go func() {
		_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	receiveBrokerSignal(t, approver.started, "approval was not requested before stop")

	broker.StopWithAuditEvent(context.Background(), audit.Event{})

	receiveBrokerSignal(t, approver.canceled, "stop did not cancel pending approval")
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrDaemonStopped) {
			t.Fatalf("deliverExec error = %v, want daemon stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deliverExec did not return after daemon stop")
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver called after stopped pending approval: %v", calls)
	}
	events := aud.Events()
	if !containsAuditEvent(events, audit.EventDaemonStop) {
		t.Fatalf("daemon stop was not audited: %+v", events)
	}
	if containsAuditEvent(events, audit.EventApprovalGranted) ||
		containsAuditEvent(events, audit.EventCommandStarting) {
		t.Fatalf("stopped approval reached post-approval audit events: %+v", events)
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrDaemonStopped)
}

func TestBrokerStopCancelsSecretResolution(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &blockingResolver{started: make(chan struct{}), canceled: make(chan struct{})}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	errCh := make(chan error, 1)
	go func() {
		_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	receiveBrokerSignal(t, resolver.started, "secret resolution did not start before stop")

	broker.StopWithAuditEvent(context.Background(), audit.Event{})

	receiveBrokerSignal(t, resolver.canceled, "stop did not cancel secret resolution")
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrDaemonStopped) {
			t.Fatalf("deliverExec error = %v, want daemon stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deliverExec did not return after daemon stop")
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatalf("stopped resolution reached command_starting audit: %+v", aud.Events())
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrDaemonStopped)
}

func TestBrokerRollsBackReusableApprovalWhenCacheInsertFails(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	store := policy.NewStore(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })
	cache := newFailingSecretCache(errors.New("mlock failed"), 1)
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}}
	broker := newTestBroker(t, Options{
		Store:    store,
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err == nil {
		t.Fatal("expected cache insertion failure")
	}
	if len(cache.clearedScopes) != 1 {
		t.Fatalf("cleared scopes = %v, want one rollback clear", cache.clearedScopes)
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("reusable approval survived cache insertion failure: %v", err)
	}
	if approver.calls != 1 {
		t.Fatalf("approver calls after failed insert = %d, want 1", approver.calls)
	}

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("fresh retry after cache failure returned error: %v", err)
	}
	if approver.calls != 2 {
		t.Fatalf("retry did not use fresh approval path; approver calls = %d", approver.calls)
	}
	if grant.Env["TOKEN"] != "value" {
		t.Fatalf("retry grant = %+v, want TOKEN value", grant)
	}
	if grant.approvalID == "" {
		t.Fatal("retry should create a usable reusable approval")
	}
}

func TestBrokerRollsBackReusableApprovalWhenCommandStartingAuditFails(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	store := policy.NewStore(func() time.Time { return now })
	cache := newFailingSecretCache(nil, 0)
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	broker := newTestBroker(t, Options{
		Store:    store,
		Cache:    cache,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit: &memoryAudit{errByType: map[audit.EventType]error{
			audit.EventCommandStarting: errors.New("disk full"),
		}},
	})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("expected command_starting audit failure, got %v", err)
	}
	if len(cache.clearedScopes) != 1 {
		t.Fatalf("cleared scopes = %v, want one command_starting rollback clear", cache.clearedScopes)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: cache.clearedScopes[0], Ref: ref}); ok {
		t.Fatal("reusable cache scope survived command_starting audit failure")
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("reusable approval survived command_starting audit failure: %v", err)
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrUnknownRequest)
}

func TestBrokerRollsBackReusableReservationWhenReuseAuditFails(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	aud := &memoryAudit{}
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	broker := newTestBroker(t, Options{
		Now:      func() time.Time { return now },
		Cache:    secretcache.NewSecretCache(),
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	aud.errByType = map[audit.EventType]error{audit.EventApprovalReused: errors.New("disk full")}
	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("expected approval_reused audit failure, got %v", err)
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_2", ""), ErrUnknownRequest)

	aud.errByType = nil
	retry, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), req)
	if err != nil {
		t.Fatalf("retry after approval_reused audit failure returned error: %v", err)
	}
	if retry.approvalID != first.approvalID {
		t.Fatalf("retry used approval id %q, want original %q", retry.approvalID, first.approvalID)
	}
	if approver.calls != 1 {
		t.Fatalf("retry used fresh approval path after rollback; approver calls = %d", approver.calls)
	}
	if len(resolver.Calls()) != 1 {
		t.Fatalf("retry refetched cached secret after rollback: %v", resolver.Calls())
	}
}

func TestBrokerReportLifecycleValidatesNonceAndAudits(t *testing.T) {
	t.Parallel()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req); err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if err := broker.ReportStarted(context.Background(), testCorrelation("req_1", "wrong"), 1234); !errors.Is(err, protocol.ErrInvalidNonce) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	if err := broker.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 1234); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := broker.ReportCompleted(context.Background(), testCorrelation("req_1", "nonce_1"), 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error: %v", err)
	}

	got := []audit.EventType{}
	for _, event := range aud.Events() {
		got = append(got, event.Type)
	}
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

func TestBrokerClientDisconnectAfterPayloadAuditsWithoutKillingProcess(t *testing.T) {
	t.Parallel()

	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	broker.ClientDisconnected(context.Background(), "req_1")

	events := aud.Events()
	if len(events) != 5 || events[4].Type != audit.EventExecClientDisconnectedAfterPayload {
		t.Fatalf("expected disconnect audit, got %+v", events)
	}
}

func TestBrokerClientDisconnectAuditFailureIsBestEffort(t *testing.T) {
	t.Parallel()

	aud := &memoryAudit{
		errByType: map[audit.EventType]error{
			audit.EventExecClientDisconnectedAfterPayload: errors.New("audit unavailable"),
		},
	}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	broker.ClientDisconnected(context.Background(), "req_1")

	if err := broker.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 1234); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("disconnect audit failure left request active, ReportStarted = %v", err)
	}
}

func TestBrokerClientDisconnectAfterStartAuditsIncompleteLifecycle(t *testing.T) {
	t.Parallel()

	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": canarySecretValue}},
		Audit:    aud,
	})
	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if err := broker.ReportStarted(context.Background(), testCorrelation("req_1", "nonce_1"), 1234); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	broker.ClientDisconnected(context.Background(), "req_1")

	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventCommandStarting,
		audit.EventCommandStarted,
		audit.EventExecClientDisconnectedAfterStart,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	disconnect := events[len(events)-1]
	if disconnect.ChildPID == nil || *disconnect.ChildPID != 1234 {
		t.Fatalf("disconnect child pid = %v, want 1234", disconnect.ChildPID)
	}
	assertAuditEventsValueFree(t, events)
}

func TestBrokerStopAuditFailureIsBestEffort(t *testing.T) {
	t.Parallel()

	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit: &memoryAudit{
			errByType: map[audit.EventType]error{
				audit.EventDaemonStop: errors.New("audit unavailable"),
			},
		},
	})

	broker.StopWithAuditEvent(context.Background(), audit.Event{})

	if _, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); !errors.Is(err, ErrDaemonStopped) {
		t.Fatalf("stop audit failure left broker running, handleExec = %v", err)
	}
}

func TestBrokerAuditFailureStopsBeforePayload(t *testing.T) {
	t.Parallel()

	approver := &mockApprover{decision: approval.Decision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{err: errors.New("disk full")},
	})
	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	}))
	if !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("expected audit failure, got %v", err)
	}
	if approver.calls != 0 {
		t.Fatalf("approver called after audit preflight failure: %d", approver.calls)
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("resolver called after audit preflight failure: %v", resolver.Calls())
	}
}
