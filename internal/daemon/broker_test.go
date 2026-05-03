package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

const canarySecretValue = "synthetic-secret-value"

type mockApprover struct {
	decision ApprovalDecision
	err      error
	calls    int
	order    *[]string
}

func (m *mockApprover) ApproveExec(
	_ context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (ApprovalDecision, error) {
	m.calls++
	if m.order != nil {
		*m.order = append(*m.order, "approve")
	}
	return m.decision, m.err
}

type recordingApprover struct {
	decision ApprovalDecision
	seen     chan request.ExecRequest
}

func (r *recordingApprover) ApproveExec(
	_ context.Context,
	_ string,
	_ string,
	req request.ExecRequest,
) (ApprovalDecision, error) {
	r.seen <- req
	return r.decision, nil
}

type sleepingApprover struct {
	delay    time.Duration
	decision ApprovalDecision
	calls    int
}

func (s *sleepingApprover) ApproveExec(
	_ context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (ApprovalDecision, error) {
	s.calls++
	time.Sleep(s.delay)
	return s.decision, nil
}

type contextExpiringApprover struct {
	done chan struct{}
}

func (a *contextExpiringApprover) ApproveExec(
	ctx context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (ApprovalDecision, error) {
	<-ctx.Done()
	close(a.done)
	return ApprovalDecision{}, ErrRequestExpired
}

type contextDenyingApprover struct {
	done chan struct{}
}

func (a *contextDenyingApprover) ApproveExec(
	ctx context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (ApprovalDecision, error) {
	<-ctx.Done()
	close(a.done)
	return ApprovalDecision{}, ErrApprovalDenied
}

type blockingApprover struct {
	started  chan struct{}
	canceled chan struct{}
}

func (a *blockingApprover) ApproveExec(
	ctx context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (ApprovalDecision, error) {
	close(a.started)
	<-ctx.Done()
	close(a.canceled)
	return ApprovalDecision{}, ctx.Err()
}

type mockResolver struct {
	mu     sync.Mutex
	values map[string]string
	errs   map[string]error
	calls  []string
	order  *[]string
}

func (m *mockResolver) Resolve(_ context.Context, ref string, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := resolverCallKey(ref, account)
	m.calls = append(m.calls, key)
	if m.order != nil {
		*m.order = append(*m.order, "resolve:"+key)
	}
	if err := m.errs[key]; err != nil {
		return "", err
	}
	return m.values[key], nil
}

func (m *mockResolver) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

type cancelObservingResolver struct {
	failRef      string
	failErr      error
	slowRef      string
	slowStarted  chan struct{}
	slowCanceled chan struct{}
}

func (r *cancelObservingResolver) Resolve(ctx context.Context, ref string, _ string) (string, error) {
	switch ref {
	case r.failRef:
		select {
		case <-r.slowStarted:
			return "", r.failErr
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
			return "", errors.New("slow resolver did not start")
		}
	case r.slowRef:
		close(r.slowStarted)
		select {
		case <-ctx.Done():
			close(r.slowCanceled)
			return "", ctx.Err()
		case <-time.After(time.Second):
			return "", errors.New("slow resolver was not canceled")
		}
	default:
		return canarySecretValue, nil
	}
}

type deadlineObservingResolver struct {
	done chan struct{}
}

func (r *deadlineObservingResolver) Resolve(ctx context.Context, _ string, _ string) (string, error) {
	<-ctx.Done()
	close(r.done)
	return "", ctx.Err()
}

type blockingResolver struct {
	started  chan struct{}
	canceled chan struct{}
}

func (r *blockingResolver) Resolve(ctx context.Context, _ string, _ string) (string, error) {
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	return "", ctx.Err()
}

type advancingResolver struct {
	value   string
	advance func()
}

func (r *advancingResolver) Resolve(_ context.Context, _ string, _ string) (string, error) {
	r.advance()
	return r.value, nil
}

type failingSecretCache struct {
	err           error
	failPuts      int
	puts          int
	delegate      *policy.SecretCache
	clearedScopes []string
}

func newFailingSecretCache(err error, failPuts int) *failingSecretCache {
	return &failingSecretCache{err: err, failPuts: failPuts, delegate: policy.NewSecretCache()}
}

func (c *failingSecretCache) Put(scopeID string, ref string, account string, value string) error {
	if c.puts < c.failPuts {
		c.puts++
		return c.err
	}
	c.puts++
	return c.delegate.Put(scopeID, ref, account, value)
}

func (c *failingSecretCache) Get(scopeID string, ref string, account string) (string, bool) {
	return c.delegate.Get(scopeID, ref, account)
}

func (c *failingSecretCache) ClearScope(scopeID string) {
	c.clearedScopes = append(c.clearedScopes, scopeID)
	c.delegate.ClearScope(scopeID)
}

func (c *failingSecretCache) Clear() {
	c.delegate.Clear()
}

func resolverCallKey(ref string, account string) string {
	if account == "" {
		return ref
	}
	return account + "|" + ref
}

type memoryAudit struct {
	mu        sync.Mutex
	err       error
	errByType map[audit.EventType]error
	events    []audit.Event
	reuses    []policy.ReuseAuditEvent
}

func (m *memoryAudit) Record(_ context.Context, event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if err := m.errByType[event.Type]; err != nil {
		return err
	}
	m.events = append(m.events, event)
	return nil
}

type contextCheckingAudit struct {
	memoryAudit
}

func (m *contextCheckingAudit) Record(ctx context.Context, event audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.memoryAudit.Record(ctx, event)
}

type callbackAudit struct {
	memoryAudit

	onRecord func(audit.Event)
}

func (m *callbackAudit) Record(ctx context.Context, event audit.Event) error {
	if m.onRecord != nil {
		m.onRecord(event)
	}
	return m.memoryAudit.Record(ctx, event)
}

func (m *memoryAudit) ApprovalReused(_ context.Context, event policy.ReuseAuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.reuses = append(m.reuses, event)
	return nil
}

func (m *memoryAudit) Preflight(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

func (m *memoryAudit) Events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

func (m *memoryAudit) Reuses() []policy.ReuseAuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.reuses)
}

func TestBrokerApprovesBeforeResolvingAndAuditsBeforePayload(t *testing.T) {
	t.Parallel()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	order := []string{}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}, order: &order},
		Resolver: &mockResolver{values: map[string]string{
			"op://Example/Item/token": canarySecretValue,
		}, order: &order},
		Audit: aud,
	})

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
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
		name:      "denial",
		err:       ErrApprovalDenied,
		eventType: audit.EventApprovalDenied,
		errorCode: "approval_denied",
	})
}

func TestBrokerApprovalTimeoutAuditsOutcomeWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	assertApprovalFailureAudited(t, approvalFailureAuditCase{
		name:      "timeout",
		err:       ErrRequestExpired,
		eventType: audit.EventApprovalTimedOut,
		errorCode: "request_expired",
	})
}

func TestBrokerApprovalTimeoutAuditIgnoresExpiredRequestContext(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	assertDeadlineApprovalFailureAudited(t, deadlineApprovalFailureCase{
		approver:  &contextExpiringApprover{done: done},
		done:      done,
		err:       ErrRequestExpired,
		eventType: audit.EventApprovalTimedOut,
		errorCode: "request_expired",
		name:      "approval timeout",
	})
}

func TestBrokerLateDenialAuditsDenialWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	assertDeadlineApprovalFailureAudited(t, deadlineApprovalFailureCase{
		approver:  &contextDenyingApprover{done: done},
		done:      done,
		err:       ErrApprovalDenied,
		eventType: audit.EventApprovalDenied,
		errorCode: "approval_denied",
		name:      "late denial",
	})
}

type deadlineApprovalFailureCase struct {
	approver  Approver
	done      <-chan struct{}
	err       error
	eventType audit.EventType
	errorCode string
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
	broker, err := NewBroker(BrokerOptions{
		Now:      time.Now,
		Approver: tc.approver,
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}

	_, err = broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
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
	if events[1].ErrorCode != tc.errorCode {
		t.Fatalf("%s error code = %q", tc.name, events[1].ErrorCode)
	}
}

type approvalFailureAuditCase struct {
	name      string
	err       error
	eventType audit.EventType
	errorCode string
}

func assertApprovalFailureAudited(t *testing.T, tc approvalFailureAuditCase) {
	t.Helper()

	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": canarySecretValue}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{err: tc.err},
		Resolver: resolver,
		Audit:    aud,
	})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	}))
	if !errors.Is(err, tc.err) {
		t.Fatalf("expected approval %s, got %v", tc.name, err)
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("resolver was called after approval %s: %v", tc.name, resolver.Calls())
	}
	events := aud.Events()
	want := []audit.EventType{audit.EventApprovalRequested, tc.eventType}
	if got := auditEventTypes(events); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
	if events[1].ErrorCode != tc.errorCode {
		t.Fatalf("approval %s error code = %q", tc.name, events[1].ErrorCode)
	}
	assertAuditEventsValueFree(t, events)
}

func TestBrokerDeduplicatesRefsAndPreservesEmptyValues(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &mockResolver{values: map[string]string{ref: ""}}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: ref},
		{Alias: "TOKEN_COPY", Ref: ref},
	}))
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
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
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "PERSONAL_TOKEN", Ref: ref, Account: "Personal"},
		{Alias: "WORK_TOKEN", Ref: ref, Account: "Work"},
	}))
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
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
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{
			values: map[string]string{"op://Example/Item/token": canarySecretValue},
			errs:   map[string]error{failingRef: fmt.Errorf("unreadable %s", canarySecretValue)},
		},
		Audit: aud,
	})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
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
	if failure.ErrorCode != "resolve_failed" {
		t.Fatalf("fetch failure error code = %q", failure.ErrorCode)
	}
	if len(failure.SecretRefs) != 1 || failure.SecretRefs[0].Alias != "FAIL" || failure.SecretRefs[0].Ref != failingRef {
		t.Fatalf("fetch failure refs = %+v", failure.SecretRefs)
	}
	assertAuditEventsValueFree(t, events)
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after failed fetch, got %v", err)
	}
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
	broker := newTestBroker(t, BrokerOptions{
		Approver:   &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver:   resolver,
		Audit:      aud,
		FetchLimit: 2,
	})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
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
	broker, err := NewBroker(BrokerOptions{
		Now:      time.Now,
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: resolver,
		Audit:    aud,
		Cache:    policy.NewSecretCache(),
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}

	_, err = broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrRequestExpired) {
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
	if events[len(events)-1].ErrorCode != "context_deadline_exceeded" {
		t.Fatalf("fetch failure error code = %q", events[len(events)-1].ErrorCode)
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatal("command_starting was audited after request deadline expired during fetch")
	}
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after fetch deadline expiry, got %v", err)
	}
}

func TestBrokerRejectsApprovalThatReturnsAfterRequestExpiry(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	now := time.Now()
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 25 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	approver := &sleepingApprover{
		delay:    50 * time.Millisecond,
		decision: ApprovalDecision{Approved: true, Reusable: true},
	}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &memoryAudit{}
	broker, err := NewBroker(BrokerOptions{
		Now:      time.Now,
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}

	_, err = broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrRequestExpired) {
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
	broker, err := NewBroker(BrokerOptions{
		Now:      nowFn,
		Cache:    cache,
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: resolver,
		Audit:    aud,
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}

	_, err = broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("expected request expiry after resolution, got %v", err)
	}
	if cache.puts != 0 {
		t.Fatalf("cache writes after request expiry = %d, want 0", cache.puts)
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatal("command_starting was audited after request expired post-resolution")
	}
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after post-resolution expiry, got %v", err)
	}
}

func TestBrokerReusableApprovalUsesCacheAndForceRefreshRefetches(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	cache := policy.NewSecretCache()
	broker := newTestBroker(t, BrokerOptions{Approver: approver, Resolver: resolver, Audit: aud, Cache: cache})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if first.ApprovalID == "" {
		t.Fatal("expected reusable approval id")
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}

	resolver.values[ref] = "second"
	second, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", req)
	if err != nil {
		t.Fatalf("second HandleExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("reusable approval did not use cached value: %+v", second.Env)
	}
	if len(resolver.Calls()) != 1 {
		t.Fatalf("cached reusable approval refetched without force-refresh: %v", resolver.Calls())
	}
	if reuses := aud.Reuses(); len(reuses) != 1 {
		t.Fatalf("expected approval_reused audit metadata, got %+v", reuses)
	}
	if err := broker.MarkPayloadDelivered("req_2"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}

	force := req
	force.ForceRefresh = true
	third, err := broker.HandleExec(context.Background(), "req_3", "nonce_3", force)
	if err != nil {
		t.Fatalf("force-refresh HandleExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("force refresh did not update cached value: %+v", third.Env)
	}
	if value, ok := cache.Get(first.ApprovalID, ref, ""); !ok || value != "second" {
		t.Fatalf("force refresh cache value = %q, %v; want second, true", value, ok)
	}
	if len(resolver.Calls()) != 2 {
		t.Fatalf("force-refresh did not refetch once: %v", resolver.Calls())
	}
	events := aud.Events()
	if !containsAuditEvent(events, audit.EventApprovalRefreshed) {
		t.Fatalf("force-refresh did not emit refresh audit event: %+v", events)
	}
}

func TestBrokerReusableApprovalMissesWhenEnvironmentFingerprintChanges(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
		Cache:    policy.NewSecretCache(),
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}

	resolver.values[ref] = "second"
	changed := req
	changed.EnvironmentFingerprint = request.EnvironmentFingerprint([]string{
		"PATH=/opt/homebrew/bin",
		"NODE_OPTIONS=--require ./changed.js",
	})
	second, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", changed)
	if err != nil {
		t.Fatalf("second HandleExec returned error: %v", err)
	}
	if second.ApprovalID == first.ApprovalID {
		t.Fatalf("changed environment reused approval %q", first.ApprovalID)
	}
	if second.Env["TOKEN"] != "second" {
		t.Fatalf("changed environment used cached value from old approval: %+v", second.Env)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after env fingerprint change", approver.calls)
	}
	if len(resolver.Calls()) != 2 {
		t.Fatalf("resolver calls = %v, want refetch after env fingerprint change", resolver.Calls())
	}
	if reuses := aud.Reuses(); len(reuses) != 0 {
		t.Fatalf("changed environment emitted reuse audit: %+v", reuses)
	}
}

func TestBrokerReusableApprovalUsesApprovedUseLimit(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	cache := policy.NewSecretCache()
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if first.ApprovalID == "" {
		t.Fatal("expected reusable approval id")
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("first MarkPayloadDelivered returned error: %v", err)
	}

	resolver.values[ref] = "second"
	second, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", req)
	if err != nil {
		t.Fatalf("second HandleExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("second delivery did not reuse cached first value: %+v", second.Env)
	}
	if err := broker.MarkPayloadDelivered("req_2"); err != nil {
		t.Fatalf("second MarkPayloadDelivered returned error: %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("two-use approval cache scope remained after two deliveries")
	}

	third, err := broker.HandleExec(context.Background(), "req_3", "nonce_3", req)
	if err != nil {
		t.Fatalf("third HandleExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after exhaustion used stale value: %+v", third.Env)
	}
	if third.ApprovalID == first.ApprovalID {
		t.Fatalf("fresh approval reused exhausted approval id %q", first.ApprovalID)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after two deliveries", approver.calls)
	}
}

func TestBrokerReusableApprovalMissesWhenUseLimitChanges(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    policy.NewSecretCache(),
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}

	resolver.values[ref] = "second"
	changed := req
	changed.ReusableUses = 3
	approver.decision.ReusableUses = 3
	second, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", changed)
	if err != nil {
		t.Fatalf("second HandleExec returned error: %v", err)
	}
	if second.ApprovalID == first.ApprovalID {
		t.Fatalf("changed use limit reused approval %q", first.ApprovalID)
	}
	if second.Env["TOKEN"] != "second" {
		t.Fatalf("changed use limit used cached value from old approval: %+v", second.Env)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after reusable use limit change", approver.calls)
	}
}

func TestBrokerClearsReusableCacheOnExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	broker, err := NewBroker(BrokerOptions{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); !ok {
		t.Fatal("expected first reusable value in cache")
	}

	now = req.ExpiresAt.Add(time.Second)
	resolver.values[ref] = "second"
	next := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	second, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", next)
	if err != nil {
		t.Fatalf("second HandleExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after expiry used stale value: %+v", second.Env)
	}
	if second.ApprovalID == first.ApprovalID {
		t.Fatalf("fresh approval reused expired approval id %q", second.ApprovalID)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("expired reusable approval cache scope remained reachable")
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresDuringForceRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	broker, err := NewBroker(BrokerOptions{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); !ok {
		t.Fatal("expected reusable value in cache before force refresh")
	}

	now = req.ExpiresAt.Add(-time.Millisecond)
	broker.resolver = &advancingResolver{
		value: "second",
		advance: func() {
			now = req.ExpiresAt.Add(time.Second)
		},
	}
	force := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	force.ForceRefresh = true

	_, err = broker.HandleExec(context.Background(), "req_2", "nonce_2", force)
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("expected expired reusable approval during refresh, got %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("expired reusable approval cache scope remained after force refresh")
	}
	if _, err := broker.store.FindReusable(context.Background(), req, nil); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("expired reusable approval remained in store: %v", err)
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresBeforePayloadDelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	broker, err := NewBroker(BrokerOptions{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}

	now = req.ExpiresAt.Add(-time.Millisecond)
	reuse := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	if _, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", reuse); err != nil {
		t.Fatalf("reuse HandleExec returned error before payload delivery: %v", err)
	}

	now = req.ExpiresAt.Add(time.Second)
	if err := broker.MarkPayloadDelivered("req_2"); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("expected reusable approval expiry before payload delivery, got %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("expired reusable approval cache scope remained before payload delivery")
	}
	if err := broker.MarkPayloadDelivered("req_2"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("expired request should no longer accept payload delivery, got %v", err)
	}
}

func TestBrokerReusableCacheExpiresWithoutMatchingRequest(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	broker, err := NewBroker(BrokerOptions{
		Now:      time.Now,
		Cache:    cache,
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 100 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	if _, ok := cache.Get(grant.ApprovalID, ref, ""); !ok {
		t.Fatal("expected reusable value in cache before expiry")
	}

	waitForCacheScopeCleared(t, cache, grant.ApprovalID, ref, "")
}

func TestBrokerClearsReusableCacheOnUseExhaustion(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	broker := newTestBroker(t, BrokerOptions{Approver: approver, Resolver: resolver, Audit: &memoryAudit{}, Cache: cache})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("first HandleExec returned error: %v", err)
	}
	for i := 1; i <= policy.DefaultReusableUses; i++ {
		requestID := fmt.Sprintf("req_%d", i)
		nonce := fmt.Sprintf("nonce_%d", i)
		if i > 1 {
			if _, err := broker.HandleExec(context.Background(), requestID, nonce, req); err != nil {
				t.Fatalf("reuse %d HandleExec returned error: %v", i, err)
			}
		}
		if err := broker.MarkPayloadDelivered(requestID); err != nil {
			t.Fatalf("reuse %d MarkPayloadDelivered returned error: %v", i, err)
		}
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("exhausted reusable approval cache scope remained reachable")
	}

	resolver.values[ref] = "second"
	fresh, err := broker.HandleExec(context.Background(), "req_4", "nonce_4", req)
	if err != nil {
		t.Fatalf("fresh HandleExec returned error: %v", err)
	}
	if fresh.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after exhaustion used stale value: %+v", fresh.Env)
	}
	if fresh.ApprovalID == first.ApprovalID {
		t.Fatalf("fresh approval reused exhausted approval id %q", fresh.ApprovalID)
	}
}

func TestBrokerStopClearsReusableCache(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if _, ok := cache.Get(grant.ApprovalID, ref, ""); !ok {
		t.Fatal("expected reusable value in cache")
	}
	broker.Stop(context.Background())
	if _, ok := cache.Get(grant.ApprovalID, ref, ""); ok {
		t.Fatal("daemon stop left reusable cache scope reachable")
	}
}

func TestBrokerStopCancelsPendingApproval(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &blockingApprover{started: make(chan struct{}), canceled: make(chan struct{})}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	errCh := make(chan error, 1)
	go func() {
		_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	receiveBrokerSignal(t, approver.started, "approval was not requested before stop")

	broker.Stop(context.Background())

	receiveBrokerSignal(t, approver.canceled, "stop did not cancel pending approval")
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrDaemonStopped) {
			t.Fatalf("HandleExec error = %v, want daemon stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleExec did not return after daemon stop")
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
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrDaemonStopped) {
		t.Fatalf("MarkPayloadDelivered after stop = %v, want daemon stopped", err)
	}
}

func TestBrokerStopCancelsSecretResolution(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	resolver := &blockingResolver{started: make(chan struct{}), canceled: make(chan struct{})}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	errCh := make(chan error, 1)
	go func() {
		_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
		errCh <- err
	}()
	receiveBrokerSignal(t, resolver.started, "secret resolution did not start before stop")

	broker.Stop(context.Background())

	receiveBrokerSignal(t, resolver.canceled, "stop did not cancel secret resolution")
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrDaemonStopped) {
			t.Fatalf("HandleExec error = %v, want daemon stopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleExec did not return after daemon stop")
	}
	if containsAuditEvent(aud.Events(), audit.EventCommandStarting) {
		t.Fatalf("stopped resolution reached command_starting audit: %+v", aud.Events())
	}
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrDaemonStopped) {
		t.Fatalf("MarkPayloadDelivered after stop = %v, want daemon stopped", err)
	}
}

func TestBrokerStopBlocksReusablePayloadAfterCachedValuesAreRead(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	var broker *Broker
	var stopOnce sync.Once
	aud := &callbackAudit{}
	aud.onRecord = func(event audit.Event) {
		if event.Type != audit.EventCommandStarting || event.RequestID != "req_2" {
			return
		}
		stopOnce.Do(func() {
			broker.Stop(context.Background())
		})
	}
	broker = newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: resolver,
		Audit:    aud,
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("initial HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("initial MarkPayloadDelivered returned error: %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); !ok {
		t.Fatal("expected reusable value in cache before stop")
	}

	_, err = broker.HandleExec(context.Background(), "req_2", "nonce_2", req)
	if !errors.Is(err, ErrDaemonStopped) {
		t.Fatalf("reusable HandleExec after stop during command_starting = %v, want daemon stopped", err)
	}
	if err := broker.MarkPayloadDelivered("req_2"); !errors.Is(err, ErrDaemonStopped) {
		t.Fatalf("reusable MarkPayloadDelivered after stop = %v, want daemon stopped", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("daemon stop left reusable cache value reachable")
	}
	if calls := resolver.Calls(); !reflect.DeepEqual(calls, []string{ref}) {
		t.Fatalf("resolver calls = %v, want only initial fresh resolution", calls)
	}
}

func TestBrokerRollsBackReusableApprovalWhenCacheInsertFails(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	store := policy.NewStore(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })
	cache := newFailingSecretCache(errors.New("mlock failed"), 1)
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	broker := newTestBroker(t, BrokerOptions{
		Store:    store,
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err == nil {
		t.Fatal("expected cache insertion failure")
	}
	if len(cache.clearedScopes) != 1 {
		t.Fatalf("cleared scopes = %v, want one rollback clear", cache.clearedScopes)
	}
	if _, err := store.FindReusable(context.Background(), req, nil); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("reusable approval survived cache insertion failure: %v", err)
	}
	if approver.calls != 1 {
		t.Fatalf("approver calls after failed insert = %d, want 1", approver.calls)
	}

	grant, err := broker.HandleExec(context.Background(), "req_2", "nonce_2", req)
	if err != nil {
		t.Fatalf("fresh retry after cache failure returned error: %v", err)
	}
	if approver.calls != 2 {
		t.Fatalf("retry did not use fresh approval path; approver calls = %d", approver.calls)
	}
	if grant.Env["TOKEN"] != "value" {
		t.Fatalf("retry grant = %+v, want TOKEN value", grant)
	}
	if grant.ApprovalID == "" {
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
	broker := newTestBroker(t, BrokerOptions{
		Store:    store,
		Cache:    cache,
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit: &memoryAudit{errByType: map[audit.EventType]error{
			audit.EventCommandStarting: errors.New("disk full"),
		}},
	})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("expected command_starting audit failure, got %v", err)
	}
	if len(cache.clearedScopes) != 1 {
		t.Fatalf("cleared scopes = %v, want one command_starting rollback clear", cache.clearedScopes)
	}
	if _, ok := cache.Get(cache.clearedScopes[0], ref, ""); ok {
		t.Fatal("reusable cache scope survived command_starting audit failure")
	}
	if _, err := store.FindReusable(context.Background(), req, nil); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("reusable approval survived command_starting audit failure: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after command_starting audit failure, got %v", err)
	}
}

func TestBrokerRollsBackForceRefreshWhenRefreshAuditFails(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := policy.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Cache:    cache,
		Approver: approver,
		Resolver: resolver,
		Audit:    aud,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("initial HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("initial MarkPayloadDelivered returned error: %v", err)
	}
	if value, ok := cache.Get(first.ApprovalID, ref, ""); !ok || value != "first" {
		t.Fatalf("initial cache value = %q, %v; want first, true", value, ok)
	}

	aud.errByType = map[audit.EventType]error{audit.EventApprovalRefreshed: errors.New("disk full")}
	resolver.values[ref] = "second"
	force := req
	force.ForceRefresh = true
	_, err = broker.HandleExec(context.Background(), "req_2", "nonce_2", force)
	if !errors.Is(err, ErrAuditRequired) {
		t.Fatalf("expected approval_refreshed audit failure, got %v", err)
	}
	if _, ok := cache.Get(first.ApprovalID, ref, ""); ok {
		t.Fatal("force-refresh cache scope survived refresh audit failure")
	}
	if _, err := broker.store.FindReusable(context.Background(), req, nil); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("reusable approval survived refresh audit failure: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_2"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after refresh audit failure, got %v", err)
	}

	aud.errByType = nil
	resolver.values[ref] = "third"
	retry, err := broker.HandleExec(context.Background(), "req_3", "nonce_3", req)
	if err != nil {
		t.Fatalf("fresh retry after refresh audit failure returned error: %v", err)
	}
	if retry.ApprovalID == "" || retry.ApprovalID == first.ApprovalID {
		t.Fatalf("retry approval id = %q, first = %q; want fresh reusable approval", retry.ApprovalID, first.ApprovalID)
	}
	if retry.Env["TOKEN"] != "third" {
		t.Fatalf("retry grant = %+v, want refreshed resolver value", retry)
	}
	if approver.calls != 2 {
		t.Fatalf("retry should require a fresh approval; approver calls = %d, want 2", approver.calls)
	}
}

func TestBrokerReportLifecycleValidatesNonceAndAudits(t *testing.T) {
	t.Parallel()

	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if _, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req); err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	if err := broker.ReportStarted(context.Background(), "req_1", "wrong", 1234); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	if err := broker.ReportStarted(context.Background(), "req_1", "nonce_1", 1234); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := broker.ReportCompleted(context.Background(), "req_1", "nonce_1", 0, ""); err != nil {
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
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if _, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	broker.ClientDisconnected(context.Background(), "req_1")

	events := aud.Events()
	if len(events) != 5 || events[4].Type != audit.EventExecClientDisconnectedAfterPayload {
		t.Fatalf("expected disconnect audit, got %+v", events)
	}
}

func TestBrokerClientDisconnectAfterStartAuditsIncompleteLifecycle(t *testing.T) {
	t.Parallel()

	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": canarySecretValue}},
		Audit:    aud,
	})
	if _, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	})); err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if err := broker.MarkPayloadDelivered("req_1"); err != nil {
		t.Fatalf("MarkPayloadDelivered returned error: %v", err)
	}
	if err := broker.ReportStarted(context.Background(), "req_1", "nonce_1", 1234); err != nil {
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

func TestBrokerAuditFailureStopsBeforePayload(t *testing.T) {
	t.Parallel()

	approver := &mockApprover{decision: ApprovalDecision{Approved: true}}
	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	broker := newTestBroker(t, BrokerOptions{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{err: errors.New("disk full")},
	})
	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
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

func newTestBroker(t *testing.T, opts BrokerOptions) *Broker {
	t.Helper()
	if opts.Now == nil {
		now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
		opts.Now = func() time.Time { return now }
	}
	broker, err := NewBroker(opts)
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	return broker
}

func testExecRequest(t *testing.T, secrets []request.SecretSpec) request.ExecRequest {
	t.Helper()

	return testExecRequestAt(t, time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC), secrets)
}

func testExecRequestAt(t *testing.T, now time.Time, secrets []request.SecretSpec) request.ExecRequest {
	t.Helper()

	reqSecrets := make([]request.Secret, 0, len(secrets))
	for _, spec := range secrets {
		ref, err := request.ParseSecretRef(spec.Ref)
		if err != nil {
			t.Fatalf("ParseSecretRef returned error: %v", err)
		}
		reqSecrets = append(reqSecrets, request.Secret{Alias: spec.Alias, Ref: ref, Account: spec.Account})
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
		Secrets:      reqSecrets,
		TTL:          request.DefaultExecTTL,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(request.DefaultExecTTL),
		DeliveryMode: request.DeliveryEnvExec,
	}
}

func containsAuditEvent(events []audit.Event, eventType audit.EventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func waitForCacheScopeCleared(t *testing.T, cache SecretCache, scopeID string, ref string, account string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := cache.Get(scopeID, ref, account); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cache scope %q still contained %s after expiry", scopeID, ref)
}

func receiveBrokerSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}

func auditEventTypes(events []audit.Event) []audit.EventType {
	types := make([]audit.EventType, 0, len(events))
	for _, event := range events {
		types = append(types, event.Type)
	}
	return types
}

func assertAuditEventsValueFree(t *testing.T, events []audit.Event) {
	t.Helper()
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	if bytes.Contains(encoded, []byte(canarySecretValue)) {
		t.Fatalf("audit events contain secret value %q: %s", canarySecretValue, encoded)
	}
}
