package broker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

func TestBrokerApprovesBeforeResolvingAndAuditsBeforePayload(t *testing.T) {
	t.Parallel()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	order := []string{}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}, order: &order},
		Resolver: &mockResolver{values: map[string]string{
			"op://Example/Item/token": canarySecretValue,
		}, order: &order},
		Audit: aud,
	})

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	if got := grant.Env["TOKEN"]; got != canarySecretValue {
		t.Fatalf("env TOKEN = %q", got)
	}
	if !reflect.DeepEqual(order, []string{"approve", "resolve:op://Example/Item/token"}) {
		t.Fatalf("unexpected operation order: %v", order)
	}
	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventCommandStarting,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	assertAuditEventsValueFree(t, events)
}

func TestBrokerDenialAuditsOutcomeWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	assertApprovalFailureAudited(t, approvalFailureAuditCase{
		name:             "denial",
		approverDecision: approval.Decision{Approved: false},
		wantErr:          approval.ErrApprovalDenied,
		eventType:        audit.EventApprovalDenied,
		errorCode:        protocol.ErrorCodeApprovalDenied,
	})
}

func TestBrokerComputerLockedDenialReturnsSpecificReason(t *testing.T) {
	t.Parallel()

	assertApprovalFailureAudited(t, approvalFailureAuditCase{
		name: "computer locked denial",
		approverDecision: approval.Decision{
			Approved:     false,
			DenialReason: approval.DenialReasonComputerLocked,
		},
		wantErr:     approval.ErrApprovalDenied,
		wantErrText: "Denied: Computer is locked, human approval is impossible",
		eventType:   audit.EventApprovalDenied,
		errorCode:   protocol.ErrorCodeApprovalDenied,
	})
}

func TestBrokerApprovalTimeoutAuditsOutcomeWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	assertApprovalFailureAudited(t, approvalFailureAuditCase{
		name:        "timeout",
		approverErr: approval.ErrRequestExpired,
		wantErr:     approval.ErrRequestExpired,
		eventType:   audit.EventApprovalTimedOut,
		errorCode:   protocol.ErrorCodeRequestExpired,
	})
}

func TestBrokerApprovalTimeoutAuditIgnoresExpiredRequestContext(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	assertDeadlineApprovalFailureAudited(t, deadlineApprovalFailureCase{
		approver:  &contextExpiringApprover{done: done},
		done:      done,
		err:       approval.ErrRequestExpired,
		eventType: audit.EventApprovalTimedOut,
		errorCode: protocol.ErrorCodeRequestExpired,
		name:      "approval timeout",
	})
}

func TestBrokerLateDenialAuditsDenialWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	assertDeadlineApprovalFailureAudited(t, deadlineApprovalFailureCase{
		approver:  &contextDenyingApprover{done: done},
		done:      done,
		err:       approval.ErrApprovalDenied,
		eventType: audit.EventApprovalDenied,
		errorCode: protocol.ErrorCodeApprovalDenied,
		name:      "late denial",
	})
}

type deadlineApprovalFailureCase struct {
	approver  approval.Approver
	done      <-chan struct{}
	err       error
	eventType audit.EventType
	errorCode protocol.ErrorCode
	name      string
}

func assertDeadlineApprovalFailureAudited(t *testing.T, tc deadlineApprovalFailureCase) {
	t.Helper()

	ref := "op://Example/Item/token"
	now := time.Now()
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 25 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &contextCheckingAudit{}
	broker, err := New(Options{
		Now:      time.Now,
		Approver: tc.approver,
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, tc.err) {
		t.Fatalf("expected %s, got %v", tc.err, err)
	}
	receiveBrokerSignal(t, tc.done, "approver did not observe request deadline")
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver was called after %s: %v", tc.name, calls)
	}

	events := aud.Events()
	want := []audit.EventType{audit.EventApprovalRequested, tc.eventType}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[1].ErrorCode != auditErrorCode(tc.errorCode) {
		t.Fatalf("%s error code = %q", tc.name, events[1].ErrorCode)
	}
}

type approvalFailureAuditCase struct {
	name             string
	approverDecision approval.Decision
	approverErr      error
	wantErr          error
	wantErrText      string
	eventType        audit.EventType
	errorCode        protocol.ErrorCode
}

func assertApprovalFailureAudited(t *testing.T, tc approvalFailureAuditCase) {
	t.Helper()

	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": canarySecretValue}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: tc.approverDecision, err: tc.approverErr},
		Resolver: resolver,
		Audit:    aud,
	})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	}))
	if !errors.Is(err, tc.wantErr) {
		t.Fatalf("expected approval %s, got %v", tc.name, err)
	}
	if tc.wantErrText != "" && err.Error() != tc.wantErrText {
		t.Fatalf("approval %s error = %q, want %q", tc.name, err.Error(), tc.wantErrText)
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("resolver was called after approval %s: %v", tc.name, resolver.Calls())
	}
	events := aud.Events()
	want := []audit.EventType{audit.EventApprovalRequested, tc.eventType}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[1].ErrorCode != auditErrorCode(tc.errorCode) {
		t.Fatalf("approval %s error code = %q", tc.name, events[1].ErrorCode)
	}
	assertAuditEventsValueFree(t, events)
}

func TestBrokerDeduplicatesRefsAndPreservesEmptyValues(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &mockResolver{values: map[string]string{ref: ""}}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref},
		{Alias: "TOKEN_COPY", Ref: ref},
	}))
	if err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	if len(resolver.Calls()) != 1 {
		t.Fatalf("duplicate ref was fetched %d times: %v", len(resolver.Calls()), resolver.Calls())
	}
	if value, ok := grant.Env["TOKEN"]; !ok || value != "" {
		t.Fatalf("empty TOKEN value not preserved: %+v", grant.Env)
	}
	if value, ok := grant.Env["TOKEN_COPY"]; !ok || value != "" {
		t.Fatalf("empty TOKEN_COPY value not preserved: %+v", grant.Env)
	}
}

func TestBrokerSeparatesSameRefAcrossAccounts(t *testing.T) {
	t.Parallel()

	ref := "op://Shared/Item/token"
	resolver := &mockResolver{values: map[string]string{
		resolverCallKey(ref, "Personal"): "personal-value",
		resolverCallKey(ref, "Work"):     "work-value",
	}}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "PERSONAL_TOKEN", Ref: ref, Account: "Personal"},
		{Alias: "WORK_TOKEN", Ref: ref, Account: "Work"},
	}))
	if err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	if grant.Env["PERSONAL_TOKEN"] != "personal-value" || grant.Env["WORK_TOKEN"] != "work-value" {
		t.Fatalf("same ref across accounts was not resolved separately: %+v", grant.Env)
	}
	if len(resolver.Calls()) != 2 {
		t.Fatalf("account-specific refs should not dedupe together: %v", resolver.Calls())
	}
}

func TestBrokerPartialFetchFailureReturnsNoPayload(t *testing.T) {
	t.Parallel()

	failingRef := "op://Example/Item/failing"
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{
			values: map[string]string{"op://Example/Item/token": canarySecretValue},
			errs:   map[string]error{failingRef: fmt.Errorf("unreadable %s", canarySecretValue)},
		},
		Audit: aud,
	})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
		{Alias: "FAIL", Ref: failingRef},
	}))
	if err == nil {
		t.Fatal("expected partial fetch failure")
	}
	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSecretFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	failure := events[len(events)-1]
	if failure.ErrorCode != auditErrorCode(protocol.ErrorCodeResolveFailed) {
		t.Fatalf("fetch failure error code = %q", failure.ErrorCode)
	}
	if len(failure.SecretRefs) != 1 || failure.SecretRefs[0].Alias != "FAIL" || failure.SecretRefs[0].Ref != failingRef {
		t.Fatalf("fetch failure refs = %+v", failure.SecretRefs)
	}
	assertAuditEventsValueFree(t, events)
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrUnknownRequest)
}

func TestBrokerCancelsOutstandingFetchesAfterFirstFailure(t *testing.T) {
	t.Parallel()

	failRef := "op://Example/Item/a_fail"
	slowRef := "op://Example/Item/z_slow"
	failErr := errors.New("unreadable secret")
	resolver := &cancelObservingResolver{
		failRef:      failRef,
		failErr:      failErr,
		slowRef:      slowRef,
		slowStarted:  make(chan struct{}),
		slowCanceled: make(chan struct{}),
	}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver:   &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:   resolver,
		Audit:      aud,
		FetchLimit: 2,
	})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
		{Alias: "FAIL", Ref: failRef},
		{Alias: "SLOW", Ref: slowRef},
	}))
	if !errors.Is(err, failErr) {
		t.Fatalf("expected failing ref error, got %v", err)
	}
	receiveBrokerSignal(t, resolver.slowCanceled, "slow resolver did not observe cancellation")

	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSecretFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	failure := events[len(events)-1]
	if len(failure.SecretRefs) != 1 || failure.SecretRefs[0].Alias != "FAIL" || failure.SecretRefs[0].Ref != failRef {
		t.Fatalf("fetch failure refs = %+v", failure.SecretRefs)
	}
}

func TestBrokerRequestDeadlineCancelsSlowSecretFetch(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Now()
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 50 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	resolver := &deadlineObservingResolver{done: make(chan struct{})}
	aud := &contextCheckingAudit{}
	broker, err := New(Options{
		Now:      time.Now,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: resolver,
		Audit:    aud,
		Cache:    secretcache.NewSecretCache(),
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected request expiry while resolving, got %v", err)
	}
	receiveBrokerSignal(t, resolver.done, "resolver did not observe request deadline")
	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSecretFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[len(events)-1].ErrorCode != auditErrorCode(protocol.ErrorCodeContextDeadlineExceeded) {
		t.Fatalf("fetch failure error code = %q", events[len(events)-1].ErrorCode)
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatal("command_starting was audited after request deadline expired during fetch")
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrUnknownRequest)
}

func TestBrokerRequestDeadlineReturnsWhenResolverIgnoresCancellation(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Now()
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 50 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	resolver := &contextIgnoringResolver{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer close(resolver.release)
	aud := &contextCheckingAudit{}
	broker, err := New(Options{
		Now:      time.Now,
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	receiveBrokerSignal(t, resolver.started, "secret resolution did not start before request deadline")

	select {
	case err := <-errCh:
		if !errors.Is(err, approval.ErrRequestExpired) {
			t.Fatalf("deliverExec error = %v, want request expired", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deliverExec did not return after request deadline when resolver ignored cancellation")
	}

	events := aud.Events()
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSecretFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	failure := events[len(events)-1]
	if failure.ErrorCode != auditErrorCode(protocol.ErrorCodeContextDeadlineExceeded) {
		t.Fatalf("fetch failure error code = %q", failure.ErrorCode)
	}
	if len(failure.SecretRefs) != 1 || failure.SecretRefs[0].Alias != "TOKEN" || failure.SecretRefs[0].Ref != ref {
		t.Fatalf("fetch failure refs = %+v", failure.SecretRefs)
	}
	if containsAuditEvent(events, audit.EventCommandStarting) {
		t.Fatal("command_starting was audited after hung resolver crossed request deadline")
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrUnknownRequest)
}

func TestBrokerRejectsApprovalThatReturnsAfterRequestExpiry(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = time.Minute
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	approver := &afterApprovalApprover{
		after: func() {
			now = req.ExpiresAt.Add(time.Second)
		},
		decision: approval.Decision{Approved: true, Reusable: true},
	}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &memoryAudit{}
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected request expiry after slow approval, got %v", err)
	}
	if approver.calls != 1 {
		t.Fatalf("approver calls = %d, want 1", approver.calls)
	}
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver was called after approval crossed deadline: %v", calls)
	}
	if containsAuditEvent(aud.Events(), audit.EventApprovalGranted) {
		t.Fatal("approval_granted was audited after approval crossed deadline")
	}
}

func TestBrokerStopsBeforePayloadWhenRequestExpiresAfterResolution(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	var nowMu sync.Mutex
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	resolver := &advancingResolver{
		value: "value",
		advance: func() {
			nowMu.Lock()
			now = req.ExpiresAt
			nowMu.Unlock()
		},
	}
	cache := newFailingSecretCache(nil, 0)
	aud := &memoryAudit{}
	broker, err := New(Options{
		Now:      nowFn,
		Cache:    cache,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected request expiry after resolution, got %v", err)
	}
	if cache.puts != 0 {
		t.Fatalf("cache writes after request expiry = %d, want 0", cache.puts)
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatal("command_starting was audited after request expired post-resolution")
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_1", ""), ErrUnknownRequest)
}
