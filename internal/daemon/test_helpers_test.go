package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

const canarySecretValue = "synthetic-secret-value"

func testCorrelation(requestID string, nonce string) protocol.Correlation {
	return protocol.Correlation{RequestID: requestID, Nonce: nonce}
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

type recordingApprover struct {
	decision approval.Decision
	seen     chan request.ExecRequest
}

func (r *recordingApprover) ApproveExec(
	_ context.Context,
	_ protocol.Correlation,
	req request.ExecRequest,
) (approval.Decision, error) {
	r.seen <- req
	return r.decision, nil
}

type recordingLauncher struct {
	launches launchWatcher
	mu       sync.Mutex
	launched []approval.ApprovalRequestPayload
	expected approval.ExpectedApprover
}

func (l *recordingLauncher) Launch(
	_ context.Context,
	_ string,
	payload approval.ApprovalRequestPayload,
) (approval.ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.launched = append(l.launched, payload)
	l.launches.record()
	return l.expected, nil
}

func (l *recordingLauncher) waitForLaunch(ctx context.Context, count int) error {
	return l.launches.wait(ctx, count)
}

type launchWaiter interface {
	waitForLaunch(ctx context.Context, count int) error
}

type launchWatcher struct {
	mu    sync.Mutex
	cond  *sync.Cond
	count int
}

func (w *launchWatcher) record() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initLocked()
	w.count++
	w.cond.Broadcast()
}

func (w *launchWatcher) wait(ctx context.Context, count int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.initLocked()
	stop := context.AfterFunc(ctx, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.cond.Broadcast()
	})
	defer stop()
	for w.count < count {
		if err := ctx.Err(); err != nil {
			return err
		}
		w.cond.Wait()
	}
	return ctx.Err()
}

func (w *launchWatcher) initLocked() {
	if w.cond == nil {
		w.cond = sync.NewCond(&w.mu)
	}
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

func resolverCallKey(ref string, account string) string {
	if account == "" {
		return ref
	}
	return account + "|" + ref
}

type memoryAudit struct {
	mu          sync.Mutex
	err         error
	errByType   map[audit.EventType]error
	events      []audit.Event
	subscribers []chan audit.Event
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
	for _, subscriber := range m.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
	return nil
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

func (m *memoryAudit) Subscribe() (<-chan audit.Event, func()) {
	ch := make(chan audit.Event, 64)
	m.mu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()

	unsubscribe := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		for i, subscriber := range m.subscribers {
			if subscriber == ch {
				m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
				return
			}
		}
	}
	return ch, unsubscribe
}

func newTestBroker(t *testing.T, opts daemonbroker.Options) *daemonbroker.Broker {
	t.Helper()
	if opts.Now == nil {
		now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
		opts.Now = func() time.Time { return now }
	}
	broker, err := daemonbroker.New(opts)
	if err != nil {
		t.Fatalf("broker.New returned error: %v", err)
	}
	return broker
}

func newSocketApproverForTest(t *testing.T, launcher approval.ApproverLauncher, now func() time.Time) *approval.SocketApprover {
	t.Helper()
	approver, err := approval.NewSocketApprover("/tmp/agent-secret-test.sock", launcher, now)
	if err != nil {
		t.Fatalf("approval.NewSocketApprover returned error: %v", err)
	}
	return approver
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

func approvalTestRequest(t *testing.T, expiresAt time.Time) request.ExecRequest {
	t.Helper()
	return testExecRequestAt(t, expiresAt.Add(-request.DefaultExecTTL), []request.SecretSpec{
		{Alias: "TOKEN", Ref: "op://Example/Item/token", Account: "Work"},
	})
}

func currentExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	return exe
}

func peerInfoForTest(t *testing.T, pid int, exe string) peercred.Info {
	t.Helper()
	return peercred.Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            pid,
		ExecutablePath: exe,
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
