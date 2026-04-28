package daemon

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

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

type mockResolver struct {
	mu     sync.Mutex
	values map[string]string
	errs   map[string]error
	calls  []string
	order  *[]string
}

func (m *mockResolver) Resolve(_ context.Context, ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls = append(m.calls, ref)
	if m.order != nil {
		*m.order = append(*m.order, "resolve:"+ref)
	}
	if err := m.errs[ref]; err != nil {
		return "", err
	}
	return m.values[ref], nil
}

func (m *mockResolver) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

type memoryAudit struct {
	mu     sync.Mutex
	err    error
	events []audit.Event
	reuses []policy.ReuseAuditEvent
}

func (m *memoryAudit) Record(_ context.Context, event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, event)
	return nil
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
			"op://Example/Item/token": "synthetic-secret-value",
		}, order: &order},
		Audit: aud,
	})

	grant, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", req)
	if err != nil {
		t.Fatalf("HandleExec returned error: %v", err)
	}
	if got := grant.Env["TOKEN"]; got != "synthetic-secret-value" {
		t.Fatalf("env TOKEN = %q", got)
	}
	if !reflect.DeepEqual(order, []string{"approve", "resolve:op://Example/Item/token"}) {
		t.Fatalf("unexpected operation order: %v", order)
	}
	events := aud.Events()
	if len(events) != 1 || events[0].Type != audit.EventCommandStarting {
		t.Fatalf("expected command_starting audit before payload, got %+v", events)
	}
}

func TestBrokerDenialDoesNotResolveOrAuditCommandStarting(t *testing.T) {
	t.Parallel()

	resolver := &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: false}},
		Resolver: resolver,
		Audit:    aud,
	})

	_, err := broker.HandleExec(context.Background(), "req_1", "nonce_1", testExecRequest(t, []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token"},
	}))
	if !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("expected denial, got %v", err)
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("resolver was called after denial: %v", resolver.Calls())
	}
	if events := aud.Events(); len(events) != 0 {
		t.Fatalf("audit wrote command events after denial: %+v", events)
	}
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

func TestBrokerPartialFetchFailureReturnsNoPayload(t *testing.T) {
	t.Parallel()

	failingRef := "op://Example/Item/failing"
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{
			values: map[string]string{"op://Example/Item/token": "value"},
			errs:   map[string]error{failingRef: errors.New("unreadable")},
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
	if events := aud.Events(); len(events) != 0 {
		t.Fatalf("command_starting audit should not be written after fetch failure: %+v", events)
	}
	if err := broker.MarkPayloadDelivered("req_1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request should not become active after failed fetch, got %v", err)
	}
}

func TestBrokerReusableApprovalUsesCacheAndForceRefreshRefetches(t *testing.T) {
	t.Parallel()

	ref := "op://Example/Item/token"
	approver := &mockApprover{decision: ApprovalDecision{Approved: true, Reusable: true}}
	resolver := &mockResolver{values: map[string]string{ref: "first"}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, BrokerOptions{Approver: approver, Resolver: resolver, Audit: aud})
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
	if len(resolver.Calls()) != 2 {
		t.Fatalf("force-refresh did not refetch once: %v", resolver.Calls())
	}
	events := aud.Events()
	if !containsAuditEvent(events, audit.EventApprovalRefreshed) {
		t.Fatalf("force-refresh did not emit refresh audit event: %+v", events)
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
	want := []audit.EventType{audit.EventCommandStarting, audit.EventCommandStarted, audit.EventCommandCompleted}
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
	if len(events) != 2 || events[1].Type != audit.EventExecClientDisconnectedAfterPayload {
		t.Fatalf("expected disconnect audit, got %+v", events)
	}
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
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	opts.Now = func() time.Time { return now }
	broker, err := NewBroker(opts)
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	return broker
}

func testExecRequest(t *testing.T, secrets []request.SecretSpec) request.ExecRequest {
	t.Helper()

	reqSecrets := make([]request.Secret, 0, len(secrets))
	for _, spec := range secrets {
		ref, err := request.ParseSecretRef(spec.Ref)
		if err != nil {
			t.Fatalf("ParseSecretRef returned error: %v", err)
		}
		reqSecrets = append(reqSecrets, request.Secret{Alias: spec.Alias, Ref: ref})
	}

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: "/opt/homebrew/bin/terraform",
		CWD:                "/tmp/project",
		Secrets:            reqSecrets,
		TTL:                request.DefaultExecTTL,
		ReceivedAt:         now,
		ExpiresAt:          now.Add(request.DefaultExecTTL),
		DeliveryMode:       request.DeliveryEnvExec,
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
