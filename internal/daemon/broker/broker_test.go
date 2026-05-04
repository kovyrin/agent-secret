package broker

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
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

const canarySecretValue = "synthetic-secret-value"

func testCorrelation(requestID string, nonce string) protocol.Correlation {
	return protocol.Correlation{RequestID: requestID, Nonce: nonce}
}

func deliverExecForTest(
	ctx context.Context,
	b *Broker,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (Grant, error) {
	return deliverExecWithWriteForTest(ctx, b, correlation, req, func(protocol.ExecResponsePayload, time.Time) error {
		return nil
	})
}

func deliverExecWithWriteForTest(
	ctx context.Context,
	b *Broker,
	correlation protocol.Correlation,
	req request.ExecRequest,
	write func(protocol.ExecResponsePayload, time.Time) error,
) (Grant, error) {
	return b.HandleExecDelivery(ctx, correlation, req, write)
}

func requireActiveRequest(t *testing.T, b *Broker, correlation protocol.Correlation) {
	t.Helper()
	if _, err := b.activeRequest(correlation); err != nil {
		t.Fatalf("active request %q returned error: %v", correlation.RequestID, err)
	}
}

func requireNoActiveRequest(t *testing.T, b *Broker, correlation protocol.Correlation, want error) {
	t.Helper()
	if _, err := b.activeRequest(correlation); !errors.Is(err, want) {
		t.Fatalf("active request %q = %v, want %v", correlation.RequestID, err, want)
	}
}

func TestBrokerActivatesExecBeforePayloadWriteAndClearsOnWriteFailure(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	correlation := testCorrelation("req_1", "nonce_1")
	writeErr := errors.New("write failed")

	_, err := deliverExecWithWriteForTest(
		context.Background(),
		broker,
		correlation,
		testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}}),
		func(protocol.ExecResponsePayload, time.Time) error {
			requireActiveRequest(t, broker, correlation)
			return writeErr
		},
	)
	if !errors.Is(err, writeErr) {
		t.Fatalf("deliverExec error = %v, want write failure", err)
	}
	requireNoActiveRequest(t, broker, correlation, ErrUnknownRequest)
}

type mockApprover struct {
	decision approval.Decision
	err      error
	calls    int
	order    *[]string
}

func (m *mockApprover) ApproveExec(
	_ context.Context,
	_ protocol.Correlation,
	_ request.ExecRequest,
) (approval.Decision, error) {
	m.calls++
	if m.order != nil {
		*m.order = append(*m.order, "approve")
	}
	return m.decision, m.err
}

type sleepingApprover struct {
	delay    time.Duration
	decision approval.Decision
	calls    int
}

func (s *sleepingApprover) ApproveExec(
	_ context.Context,
	_ protocol.Correlation,
	_ request.ExecRequest,
) (approval.Decision, error) {
	s.calls++
	time.Sleep(s.delay)
	return s.decision, nil
}

type contextExpiringApprover struct {
	done chan struct{}
}

func (a *contextExpiringApprover) ApproveExec(
	ctx context.Context,
	_ protocol.Correlation,
	_ request.ExecRequest,
) (approval.Decision, error) {
	<-ctx.Done()
	close(a.done)
	return approval.Decision{}, approval.ErrRequestExpired
}

type contextDenyingApprover struct {
	done chan struct{}
}

func (a *contextDenyingApprover) ApproveExec(
	ctx context.Context,
	_ protocol.Correlation,
	_ request.ExecRequest,
) (approval.Decision, error) {
	<-ctx.Done()
	close(a.done)
	return approval.Decision{}, approval.ErrApprovalDenied
}

type blockingApprover struct {
	started  chan struct{}
	canceled chan struct{}
}

func (a *blockingApprover) ApproveExec(
	ctx context.Context,
	_ protocol.Correlation,
	_ request.ExecRequest,
) (approval.Decision, error) {
	close(a.started)
	<-ctx.Done()
	close(a.canceled)
	return approval.Decision{}, ctx.Err()
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

type contextIgnoringResolver struct {
	started chan struct{}
	release chan struct{}
}

func (r *contextIgnoringResolver) Resolve(ctx context.Context, _ string, _ string) (string, error) {
	close(r.started)
	<-r.release
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
	delegate      *secretcache.SecretCache
	clearedScopes []string
}

func newFailingSecretCache(err error, failPuts int) *failingSecretCache {
	return &failingSecretCache{err: err, failPuts: failPuts, delegate: secretcache.NewSecretCache()}
}

func (c *failingSecretCache) Put(key secretcache.CacheKey, value string) error {
	if c.puts < c.failPuts {
		c.puts++
		return c.err
	}
	c.puts++
	return c.delegate.Put(key, value)
}

func (c *failingSecretCache) Get(key secretcache.CacheKey) (string, bool) {
	return c.delegate.Get(key)
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
		name:      "denial",
		err:       approval.ErrApprovalDenied,
		eventType: audit.EventApprovalDenied,
		errorCode: protocol.ErrorCodeApprovalDenied,
	})
}

func TestBrokerApprovalTimeoutAuditsOutcomeWithoutResolveOrCommandStart(t *testing.T) {
	t.Parallel()

	assertApprovalFailureAudited(t, approvalFailureAuditCase{
		name:      "timeout",
		err:       approval.ErrRequestExpired,
		eventType: audit.EventApprovalTimedOut,
		errorCode: protocol.ErrorCodeRequestExpired,
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
	name      string
	err       error
	eventType audit.EventType
	errorCode protocol.ErrorCode
}

func assertApprovalFailureAudited(t *testing.T, tc approvalFailureAuditCase) {
	t.Helper()

	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": canarySecretValue}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{err: tc.err},
		Resolver: resolver,
		Audit:    aud,
	})

	_, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), testExecRequest(t, []request.SecretSpec{
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
	now := time.Now()
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.TTL = 25 * time.Millisecond
	req.ExpiresAt = req.ReceivedAt.Add(req.TTL)
	approver := &sleepingApprover{
		delay:    50 * time.Millisecond,
		decision: approval.Decision{Approved: true, Reusable: true},
	}
	resolver := &mockResolver{values: map[string]string{ref: "value"}}
	aud := &memoryAudit{}
	broker, err := New(Options{
		Now:      time.Now,
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

func TestBrokerReusableApprovalUsesCacheAndForceRefreshRefetches(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 4}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{Approver: approver, Resolver: resolver, Audit: aud, Cache: cache})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 4

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	if first.approvalID == "" {
		t.Fatal("expected reusable approval id")
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	resolver.values[ref] = "second"
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("reusable approval did not use cached value: %+v", second.Env)
	}
	if len(resolver.Calls()) != 1 {
		t.Fatalf("cached reusable approval refetched without force-refresh: %v", resolver.Calls())
	}
	reuseEvent, ok := singleAuditEvent(aud.Events(), audit.EventApprovalReused)
	if !ok {
		t.Fatalf("expected one approval_reused audit event, got %+v", aud.Events())
	}
	if reuseEvent.ApprovalID != first.approvalID {
		t.Fatalf("approval_reused approval id = %q, want %q", reuseEvent.ApprovalID, first.approvalID)
	}
	if reuseEvent.RemainingUses == nil || *reuseEvent.RemainingUses != 3 {
		t.Fatalf("approval_reused remaining uses = %v, want 3", reuseEvent.RemainingUses)
	}
	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))

	force := req
	force.ForceRefresh = true
	third, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), force)
	if err != nil {
		t.Fatalf("force-refresh deliverExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("force refresh did not update cached value: %+v", third.Env)
	}
	if value, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok || value != "second" {
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

func TestBrokerReusableApprovalUsesApprovedUseLimit(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	if first.approvalID == "" {
		t.Fatal("expected reusable approval id")
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	resolver.values[ref] = "second"
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("second delivery did not reuse cached first value: %+v", second.Env)
	}
	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("two-use approval cache scope remained after two deliveries")
	}

	third, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), req)
	if err != nil {
		t.Fatalf("third deliverExec returned error: %v", err)
	}
	if third.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after exhaustion used stale value: %+v", third.Env)
	}
	if third.approvalID == first.approvalID {
		t.Fatalf("fresh approval reused exhausted approval id %q", first.approvalID)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after two deliveries", approver.calls)
	}
}

func TestBrokerReservesReusableUseBeforePayloadDelivery(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true, ReusableUses: 2}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	broker := newTestBroker(t, Options{
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
		Cache:    secretcache.NewSecretCache(),
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	req.ReusableUses = 2

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), req)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.approvalID != first.approvalID {
		t.Fatalf(
			"second approval id = %q, want reusable approval %q",
			second.approvalID,
			first.approvalID,
		)
	}
	if second.Env["TOKEN"] != "first" {
		t.Fatalf("second delivery did not reuse cached first value: %+v", second.Env)
	}

	approver.decision = approval.Decision{Approved: false}
	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_3", "nonce_3"), req)
	if !errors.Is(err, approval.ErrApprovalDenied) {
		t.Fatalf("third deliverExec reused a reserved one-use approval; got %v", err)
	}
	if approver.calls != 2 {
		t.Fatalf("approver calls = %d, want fresh approval after reserved use exhausted cache availability", approver.calls)
	}

	requireActiveRequest(t, broker, testCorrelation("req_2", "nonce_2"))
}

func TestReusableGrantManagerPropagatesInvalidDeliveryResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	store := policy.NewStore(func() time.Time { return now })
	manager := newReusableGrantManager(
		func() time.Time { return now },
		store,
		secretcache.NewSecretCache(),
		nil,
	)
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}})
	approval, err := store.AddReusable(policy.ReusableApprovalSpec{
		Request:      req,
		ID:           "appr_1",
		Nonce:        "nonce_1",
		ReservedUses: 1,
	})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	err = manager.finishDelivery(approval.ID, policy.DeliveryResult("unknown"))
	if !errors.Is(err, policy.ErrInvalidDeliveryResult) {
		t.Fatalf("finishDelivery invalid result error = %v, want invalid delivery result", err)
	}
}

func TestBrokerClearsReusableCacheOnExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}}
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: resolver,
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok {
		t.Fatal("expected first reusable value in cache")
	}

	now = req.ExpiresAt.Add(time.Second)
	resolver.values[ref] = "second"
	next := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	second, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), next)
	if err != nil {
		t.Fatalf("second deliverExec returned error: %v", err)
	}
	if second.Env["TOKEN"] != "second" {
		t.Fatalf("fresh approval after expiry used stale value: %+v", second.Env)
	}
	if second.approvalID == first.approvalID {
		t.Fatalf("fresh approval reused expired approval id %q", second.approvalID)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained reachable")
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresDuringForceRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	approver := &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}}
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: approver,
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); !ok {
		t.Fatal("expected reusable value in cache before force refresh")
	}

	now = req.ExpiresAt.Add(-time.Millisecond)
	broker.grants.resolver = &advancingResolver{
		value: "second",
		advance: func() {
			now = req.ExpiresAt.Add(time.Second)
		},
	}
	force := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	force.ForceRefresh = true

	_, err = deliverExecForTest(context.Background(), broker, testCorrelation("req_2", "nonce_2"), force)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected expired reusable approval during refresh, got %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained after force refresh")
	}
	if _, _, err := broker.grants.reusable.store.MatchReusable(req); !errors.Is(err, policy.ErrMismatch) {
		t.Fatalf("expired reusable approval remained in store: %v", err)
	}
}

func TestBrokerRejectsReusableApprovalThatExpiresBeforePayloadDelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	broker, err := New(Options{
		Now:      func() time.Time { return now },
		Cache:    cache,
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "first"}},
		Audit:    &memoryAudit{},
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	req := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	first, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("first deliverExec returned error: %v", err)
	}
	requireActiveRequest(t, broker, testCorrelation("req_1", "nonce_1"))

	now = req.ExpiresAt.Add(-time.Millisecond)
	reuse := testExecRequestAt(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})
	_, err = deliverExecWithWriteForTest(
		context.Background(),
		broker,
		testCorrelation("req_2", "nonce_2"),
		reuse,
		func(protocol.ExecResponsePayload, time.Time) error {
			now = req.ExpiresAt.Add(time.Second)
			return approval.ErrRequestExpired
		},
	)
	if !errors.Is(err, approval.ErrRequestExpired) {
		t.Fatalf("expected reusable approval expiry before payload delivery, got %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: first.approvalID, Ref: ref}); ok {
		t.Fatal("expired reusable approval cache scope remained before payload delivery")
	}
	requireNoActiveRequest(t, broker, testCorrelation("req_2", ""), ErrUnknownRequest)
}

func TestBrokerStopClearsReusableCache(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	cache := secretcache.NewSecretCache()
	broker := newTestBroker(t, Options{
		Approver: &mockApprover{decision: approval.Decision{Approved: true, Reusable: true}},
		Resolver: &mockResolver{values: map[string]string{ref: "value"}},
		Audit:    &memoryAudit{},
		Cache:    cache,
	})
	req := testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: ref}})

	grant, err := deliverExecForTest(context.Background(), broker, testCorrelation("req_1", "nonce_1"), req)
	if err != nil {
		t.Fatalf("deliverExec returned error: %v", err)
	}
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: grant.approvalID, Ref: ref}); !ok {
		t.Fatal("expected reusable value in cache")
	}
	broker.Stop(context.Background(), audit.Event{})
	if _, ok := cache.Get(secretcache.CacheKey{ScopeID: grant.approvalID, Ref: ref}); ok {
		t.Fatal("daemon stop left reusable cache scope reachable")
	}
}

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

	broker.Stop(context.Background(), audit.Event{})

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

	broker.Stop(context.Background(), audit.Event{})

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

	broker.Stop(context.Background(), audit.Event{})

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

func newTestBroker(t *testing.T, opts Options) *Broker {
	t.Helper()
	if opts.Now == nil {
		now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
		opts.Now = func() time.Time { return now }
	}
	broker, err := New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
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
		Secrets:    reqSecrets,
		TTL:        request.DefaultExecTTL,
		ReceivedAt: now,
		ExpiresAt:  now.Add(request.DefaultExecTTL),
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

func singleAuditEvent(events []audit.Event, eventType audit.EventType) (audit.Event, bool) {
	var found audit.Event
	count := 0
	for _, event := range events {
		if event.Type != eventType {
			continue
		}
		found = event
		count++
	}
	return found, count == 1
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
