package broker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
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
	if !reflect.DeepEqual(order, []string{"approve", "resolve:Work|op://Example/Item/token"}) {
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

func TestBrokerItemDescribeApprovesBeforeMetadataLookupAndAudits(t *testing.T) {
	t.Parallel()

	order := []string{}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}, order: &order},
		Resolver: &mockResolver{order: &order},
		Audit:    aud,
	})
	req := testItemDescribeRequest(t)

	payload, err := broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("HandleItemDescribe returned error: %v", err)
	}
	if payload.Item.Item != "Item" || payload.Item.Vault != "Example" || payload.Item.Account != "Work" {
		t.Fatalf("unexpected item metadata: %+v", payload.Item)
	}
	if !reflect.DeepEqual(order, []string{"approve", "describe:Work|op://Example/Item"}) {
		t.Fatalf("unexpected operation order: %v", order)
	}
	events := aud.Events()
	want := []audit.EventType{
		audit.EventItemMetadataRequested,
		audit.EventItemMetadataGranted,
		audit.EventItemMetadataFetchStarted,
		audit.EventItemMetadataFetchCompleted,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	assertAuditEventsValueFree(t, events)
}

func TestBrokerItemDescribeResolveFailureUsesMetadataError(t *testing.T) {
	t.Parallel()

	req := testItemDescribeRequest(t)
	resolveErr := errors.New("metadata resolver unavailable")
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{errs: map[string]error{
			resolverCallKey(req.Ref.Raw, req.Account): resolveErr,
		}},
		Audit: aud,
	})

	_, err := broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, ErrItemMetadataResolveFailed) {
		t.Fatalf("HandleItemDescribe error = %v, want %v", err, ErrItemMetadataResolveFailed)
	}
	if errors.Is(err, ErrSecretResolveFailed) {
		t.Fatalf("HandleItemDescribe error = %v, should not use secret resolve sentinel", err)
	}

	events := aud.Events()
	want := []audit.EventType{
		audit.EventItemMetadataRequested,
		audit.EventItemMetadataGranted,
		audit.EventItemMetadataFetchStarted,
		audit.EventItemMetadataFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[len(events)-1].ErrorCode != auditErrorCode(protocol.ErrorCodeResolveFailed) {
		t.Fatalf("fetch failure error code = %q", events[len(events)-1].ErrorCode)
	}
}

func TestBrokerItemDescribeAuditFailuresAreRequired(t *testing.T) {
	t.Parallel()

	auditErr := errors.New("audit unavailable")
	tests := []struct {
		name              string
		audit             *memoryAudit
		approverDecision  approval.Decision
		resolverErr       error
		wantApproverCalls int
		wantResolverCalls int
	}{
		{
			name:              "preflight",
			audit:             &memoryAudit{err: auditErr},
			approverDecision:  approval.Decision{Approved: true},
			wantApproverCalls: 0,
			wantResolverCalls: 0,
		},
		{
			name: "request event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventItemMetadataRequested: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: true},
			wantApproverCalls: 0,
			wantResolverCalls: 0,
		},
		{
			name: "denial event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventApprovalDenied: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: false},
			wantApproverCalls: 1,
			wantResolverCalls: 0,
		},
		{
			name: "grant event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventItemMetadataGranted: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: true},
			wantApproverCalls: 1,
			wantResolverCalls: 0,
		},
		{
			name: "fetch started event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventItemMetadataFetchStarted: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: true},
			wantApproverCalls: 1,
			wantResolverCalls: 0,
		},
		{
			name: "fetch failed event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventItemMetadataFetchFailed: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: true},
			resolverErr:       errors.New("resolver unavailable"),
			wantApproverCalls: 1,
			wantResolverCalls: 1,
		},
		{
			name: "fetch completed event",
			audit: &memoryAudit{errByType: map[audit.EventType]error{
				audit.EventItemMetadataFetchCompleted: auditErr,
			}},
			approverDecision:  approval.Decision{Approved: true},
			wantApproverCalls: 1,
			wantResolverCalls: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := testItemDescribeRequest(t)
			approver := &mockApprover{decision: tc.approverDecision}
			resolver := &mockResolver{
				errs: map[string]error{
					resolverCallKey(req.Ref.Raw, req.Account): tc.resolverErr,
				},
			}
			broker := newTestBroker(t, Options{
				Approver: approver,
				Resolver: resolver,
				Audit:    tc.audit,
			})

			_, err := broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
			if !errors.Is(err, ErrAuditRequired) {
				t.Fatalf("HandleItemDescribe error = %v, want %v", err, ErrAuditRequired)
			}
			if approver.calls != tc.wantApproverCalls {
				t.Fatalf("approver calls = %d, want %d", approver.calls, tc.wantApproverCalls)
			}
			if calls := resolver.Calls(); len(calls) != tc.wantResolverCalls {
				t.Fatalf("resolver calls = %v, want %d calls", calls, tc.wantResolverCalls)
			}
		})
	}
}

func TestBrokerItemDescribeRequestDeadlineCancelsSlowMetadataLookup(t *testing.T) {
	t.Parallel()

	now := time.Now()
	req := testItemDescribeRequest(t)
	req.TTL = 50 * time.Millisecond
	req.ReceivedAt = now
	req.ExpiresAt = now.Add(req.TTL)
	resolver := &itemDescribeDeadlineObservingResolver{done: make(chan struct{})}
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

	_, err = broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("HandleItemDescribe error = %v, want request expired", err)
	}
	receiveBrokerSignal(t, resolver.done, "metadata resolver did not observe request deadline")

	events := aud.Events()
	want := []audit.EventType{
		audit.EventItemMetadataRequested,
		audit.EventItemMetadataGranted,
		audit.EventItemMetadataFetchStarted,
		audit.EventItemMetadataFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[len(events)-1].ErrorCode != auditErrorCode(protocol.ErrorCodeContextDeadlineExceeded) {
		t.Fatalf("fetch failure error code = %q", events[len(events)-1].ErrorCode)
	}
}

func TestBrokerItemDescribeRequestDeadlineReturnsWhenResolverIgnoresCancellation(t *testing.T) {
	t.Parallel()

	now := time.Now()
	req := testItemDescribeRequest(t)
	req.TTL = 50 * time.Millisecond
	req.ReceivedAt = now
	req.ExpiresAt = now.Add(req.TTL)
	resolver := &itemDescribeContextIgnoringResolver{
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
		_, err := broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
		errCh <- err
	}()
	receiveBrokerSignal(t, resolver.started, "metadata resolution did not start before request deadline")

	select {
	case err := <-errCh:
		if !errors.Is(err, approval.ErrRequestExpired) {
			t.Fatalf("HandleItemDescribe error = %v, want request expired", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleItemDescribe did not return after request deadline when resolver ignored cancellation")
	}

	events := aud.Events()
	want := []audit.EventType{
		audit.EventItemMetadataRequested,
		audit.EventItemMetadataGranted,
		audit.EventItemMetadataFetchStarted,
		audit.EventItemMetadataFetchFailed,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[len(events)-1].ErrorCode != auditErrorCode(protocol.ErrorCodeContextDeadlineExceeded) {
		t.Fatalf("fetch failure error code = %q", events[len(events)-1].ErrorCode)
	}
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

func TestBrokerItemDescribeApprovalDeadlineNormalizesToRequestExpired(t *testing.T) {
	t.Parallel()

	approver := &blockingApprover{started: make(chan struct{}), canceled: make(chan struct{})}
	resolver := &mockResolver{}
	aud := &contextCheckingAudit{}
	broker, err := New(Options{
		Now:      time.Now,
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	now := time.Now()
	req := testItemDescribeRequest(t)
	req.TTL = 25 * time.Millisecond
	req.ReceivedAt = now
	req.ExpiresAt = now.Add(req.TTL)

	_, err = broker.HandleItemDescribe(context.Background(), testCorrelation("req_1", "nonce_1"), req)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("HandleItemDescribe error = %v, want request expired", err)
	}
	receiveBrokerSignal(t, approver.canceled, "request deadline did not cancel pending item metadata approval")
	if calls := resolver.Calls(); len(calls) != 0 {
		t.Fatalf("resolver called after expired item metadata approval: %v", calls)
	}

	events := aud.Events()
	want := []audit.EventType{
		audit.EventItemMetadataRequested,
		audit.EventApprovalTimedOut,
	}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[len(events)-1].ErrorCode != auditErrorCode(protocol.ErrorCodeRequestExpired) {
		t.Fatalf("approval timeout error code = %q", events[len(events)-1].ErrorCode)
	}
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

type blockingSecretResolver struct {
	started chan struct{}
}

func (r *blockingSecretResolver) Resolve(ctx context.Context, _ string, _ string) (string, error) {
	r.started <- struct{}{}
	<-ctx.Done()
	return "", ctx.Err()
}

func (r *blockingSecretResolver) DescribeItem(
	_ context.Context,
	_ itemmetadata.Ref,
	_ string,
) (itemmetadata.Metadata, error) {
	return itemmetadata.Metadata{}, errors.New("unexpected item metadata lookup")
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

func TestBrokerSecretFetchUsesBoundedGoroutines(t *testing.T) {
	const fetchLimit = 2
	const refCount = 200

	resolver := &blockingSecretResolver{started: make(chan struct{}, refCount)}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver:   &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:   resolver,
		Audit:      aud,
		FetchLimit: fetchLimit,
	})
	secrets := make([]request.SecretSpec, 0, refCount)
	for index := range refCount {
		secrets = append(secrets, request.SecretSpec{
			Alias: fmt.Sprintf("TOKEN_%03d", index),
			Ref:   fmt.Sprintf("op://Example/Item/token-%03d", index),
		})
	}

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := deliverExecForTest(ctx, broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, secrets))
		errCh <- err
	}()
	for range fetchLimit {
		receiveBrokerSignal(t, resolver.started, "bounded resolver did not start expected fetches")
	}
	time.Sleep(50 * time.Millisecond)
	if delta := runtime.NumGoroutine() - before; delta > 25 {
		cancel()
		t.Fatalf("secret fetch started too many goroutines: delta=%d for %d refs", delta, refCount)
	}

	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("deliverExec returned nil error after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("deliverExec did not return after cancellation")
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
