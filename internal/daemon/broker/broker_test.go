package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
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
	return deliverExecWithWriteForTest(ctx, b, correlation, req, func(delivery *ExecDelivery) error {
		return delivery.BeforeWrite()
	})
}

func deliverExecWithWriteForTest(
	ctx context.Context,
	b *Broker,
	correlation protocol.Correlation,
	req request.ExecRequest,
	write func(*ExecDelivery) error,
) (Grant, error) {
	delivery, err := b.PrepareExecDelivery(ctx, correlation, req)
	if err != nil {
		return Grant{}, err
	}
	committed := false
	defer func() {
		if !committed {
			delivery.AbortBeforePayload()
		}
	}()
	if err := write(delivery); err != nil {
		return Grant{}, err
	}
	grant := delivery.CommitDelivered()
	committed = true
	return grant, nil
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

func testItemDescribeRequest(t *testing.T) request.ItemDescribeRequest {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	req, err := request.NewItemDescribe(request.ItemDescribeOptions{
		Reason:             "Inspect item metadata",
		Command:            []string{"agent-secret", "item", "describe", "op://Example/Item"},
		CWD:                dir,
		ResolvedExecutable: exe,
		Ref:                "op://Example/Item",
		Account:            "Work",
		TTL:                time.Minute,
		ReceivedAt:         time.Now(),
	})
	if err != nil {
		t.Fatalf("NewItemDescribe returned error: %v", err)
	}
	return req
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
		func(delivery *ExecDelivery) error {
			requireActiveRequest(t, broker, correlation)
			if err := delivery.BeforeWrite(); err != nil {
				return err
			}
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

func (m *mockApprover) Approve(
	_ context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	m.calls++
	if m.order != nil {
		*m.order = append(*m.order, "approve")
	}
	return m.decision, m.err
}

type afterApprovalApprover struct {
	after    func()
	decision approval.Decision
	calls    int
}

func (a *afterApprovalApprover) Approve(
	_ context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	a.calls++
	if a.after != nil {
		a.after()
	}
	return a.decision, nil
}

type contextExpiringApprover struct {
	done chan struct{}
}

func (a *contextExpiringApprover) Approve(
	ctx context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	<-ctx.Done()
	close(a.done)
	return approval.Decision{}, approval.ErrRequestExpired
}

type contextDenyingApprover struct {
	done chan struct{}
}

func (a *contextDenyingApprover) Approve(
	ctx context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	<-ctx.Done()
	close(a.done)
	return approval.Decision{Approved: false}, nil
}

type blockingApprover struct {
	started  chan struct{}
	canceled chan struct{}
}

func (a *blockingApprover) Approve(
	ctx context.Context,
	_ approval.ApprovalRequestPayload,
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

func (m *mockResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := resolverCallKey(ref.Raw, account)
	m.calls = append(m.calls, key)
	if m.order != nil {
		*m.order = append(*m.order, "describe:"+key)
	}
	if err := m.errs[key]; err != nil {
		return itemmetadata.Metadata{}, err
	}
	return defaultItemMetadata(ref, account), nil
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

func (r *cancelObservingResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return defaultItemMetadata(ref, account), nil
}

type deadlineObservingResolver struct {
	done chan struct{}
}

func (r *deadlineObservingResolver) Resolve(ctx context.Context, _ string, _ string) (string, error) {
	<-ctx.Done()
	close(r.done)
	return "", ctx.Err()
}

func (r *deadlineObservingResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return defaultItemMetadata(ref, account), nil
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

func (r *blockingResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return defaultItemMetadata(ref, account), nil
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

func (r *contextIgnoringResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return defaultItemMetadata(ref, account), nil
}

type advancingResolver struct {
	value   string
	advance func()
}

func (r *advancingResolver) Resolve(_ context.Context, _ string, _ string) (string, error) {
	r.advance()
	return r.value, nil
}

func (r *advancingResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return defaultItemMetadata(ref, account), nil
}

func defaultItemMetadata(ref itemmetadata.Ref, account string) itemmetadata.Metadata {
	return itemmetadata.Metadata{
		Account: account,
		Vault:   ref.Vault,
		Item:    ref.Item,
		Fields: []itemmetadata.Field{
			{
				Label:     "token",
				Type:      "Concealed",
				Concealed: true,
				Ref:       itemmetadata.BuildFieldRef(ref.Vault, ref.Item, "", "token"),
				Alias:     "TOKEN",
			},
		},
	}
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
