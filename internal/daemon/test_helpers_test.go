package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/gcpcompat"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
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

type recordingApprover struct {
	decision approval.Decision
	seen     chan approval.ApprovalRequestPayload
}

func (r *recordingApprover) Approve(
	_ context.Context,
	payload approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	r.seen <- payload
	return r.decision, nil
}

type recordingLauncher struct {
	launches launchWatcher
	mu       sync.Mutex
	count    int
	expected approval.ExpectedApprover
}

func (l *recordingLauncher) Launch(
	_ context.Context,
	_ string,
) (approval.ExpectedApprover, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count++
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

type fakeGCPMinter struct {
	tokens []gcpcompat.Token
	calls  []daemonbroker.GCPMintRequest
	err    error
}

func (m *fakeGCPMinter) MintAccessToken(_ context.Context, req daemonbroker.GCPMintRequest) (gcpcompat.Token, error) {
	m.calls = append(m.calls, req)
	if m.err != nil {
		return gcpcompat.Token{}, m.err
	}
	if len(m.tokens) == 0 {
		return gcpcompat.Token{AccessToken: "synthetic-gcp-token", ExpiresAt: time.Now().Add(req.Lifetime)}, nil
	}
	token := m.tokens[0]
	m.tokens = m.tokens[1:]
	return token, nil
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
	}, nil
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

	cwd, err := pathresolve.Strict(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize cwd: %v", err)
	}
	executableDir := filepath.Join(cwd, "bin")
	if err := os.Mkdir(executableDir, 0o750); err != nil {
		t.Fatalf("mkdir executable dir: %v", err)
	}
	executable := filepath.Join(executableDir, "terraform")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon tests need a runnable fixture executable.
		t.Fatalf("write executable: %v", err)
	}
	executableIdentity, err := fileidentity.Capture(executable)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}

	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: executable,
		ExecutableIdentity: executableIdentity,
		CWD:                cwd,
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{
			"PATH=" + executableDir,
			"NODE_OPTIONS=--require ./safe.js",
		}),
		Secrets:    reqSecrets,
		TTL:        request.DefaultExecTTL,
		ReceivedAt: now,
		ExpiresAt:  now.Add(request.DefaultExecTTL),
	}
}

func testItemDescribeRequest(t *testing.T) request.ItemDescribeRequest {
	t.Helper()

	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	cwd, err := pathresolve.Strict(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize cwd: %v", err)
	}
	executable := filepath.Join(cwd, "agent-secret")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon tests need a runnable fixture executable.
		t.Fatalf("write executable: %v", err)
	}
	ref, err := itemmetadata.ParseRef("op://Example/Item")
	if err != nil {
		t.Fatalf("ParseRef returned error: %v", err)
	}
	return request.ItemDescribeRequest{
		Reason:             "Inspect item metadata",
		Command:            []string{"agent-secret", "item", "describe", ref.Raw},
		ResolvedExecutable: executable,
		CWD:                cwd,
		Ref:                ref,
		Account:            "Work",
		TTL:                request.DefaultItemDescribeTTL,
		ReceivedAt:         now,
		ExpiresAt:          now.Add(request.DefaultItemDescribeTTL),
	}
}

func testGCPExecRequest(t *testing.T, now time.Time) request.GCPExecRequest {
	t.Helper()

	cwd, executable, executableIdentity := testGCPCommandFixture(t)
	return request.GCPExecRequest{
		Reason:                 "Inspect logs",
		Command:                []string{"gcloud", "logging", "read", "severity>=ERROR"},
		ResolvedExecutable:     executable,
		ExecutableIdentity:     executableIdentity,
		CWD:                    cwd,
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=" + filepath.Dir(executable)}),
		GoogleAccount:          "work",
		Project:                "fixture-beta",
		ServiceAccount:         "agent-beta@fixture-beta.iam.gserviceaccount.com",
		Scopes:                 []string{"https://www.googleapis.com/auth/cloud-platform"},
		ProfileName:            "beta-logs",
		ConfigRoot:             cwd,
		DeliveryMode:           request.GCPDeliveryModeTokenFile,
		TTL:                    2 * time.Minute,
		ReceivedAt:             now,
		ExpiresAt:              now.Add(2 * time.Minute),
	}
}

func testGCPSessionCreateRequest(t *testing.T, now time.Time, projectRoot string) request.GCPSessionCreateRequest {
	t.Helper()

	return request.GCPSessionCreateRequest{
		Reason:           "Run benchmark",
		GoogleAccount:    "work",
		Project:          "fixture-beta",
		ServiceAccount:   "agent-bench@fixture-beta.iam.gserviceaccount.com",
		Scopes:           []string{"https://www.googleapis.com/auth/cloud-platform"},
		ProfileName:      "fixture-beta-benchmark-run",
		ConfigSourcePath: filepath.Join(projectRoot, "agent-secret.yml"),
		ProjectRoot:      projectRoot,
		DeliveryMode:     request.GCPDeliveryModeTokenFile,
		TTL:              30 * time.Minute,
		ReceivedAt:       now,
		ExpiresAt:        now.Add(30 * time.Minute),
		MaxCommandStarts: 3,
	}
}

func testGCPSessionUseRequest(t *testing.T, handle string, cwd string) request.GCPSessionUseRequest {
	t.Helper()

	_, executable, executableIdentity := testGCPCommandFixture(t)
	return request.GCPSessionUseRequest{
		SessionHandle:          handle,
		Command:                []string{"gcloud", "compute", "instances", "list"},
		ResolvedExecutable:     executable,
		ExecutableIdentity:     executableIdentity,
		CWD:                    cwd,
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=" + filepath.Dir(executable)}),
	}
}

func testGCPCommandFixture(t *testing.T) (string, string, fileidentity.Identity) {
	t.Helper()

	cwd, err := pathresolve.Strict(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize GCP cwd: %v", err)
	}
	executableDir := filepath.Join(cwd, "bin")
	if err := os.Mkdir(executableDir, 0o750); err != nil {
		t.Fatalf("mkdir GCP executable dir: %v", err)
	}
	executable := filepath.Join(executableDir, "gcloud")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon tests need a runnable gcloud fixture executable.
		t.Fatalf("write gcloud fixture: %v", err)
	}
	executableIdentity, err := fileidentity.Capture(executable)
	if err != nil {
		t.Fatalf("capture GCP executable identity: %v", err)
	}
	return cwd, executable, executableIdentity
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

func currentExecutableClientPaths(t *testing.T) []string {
	t.Helper()
	paths, err := peertrust.CurrentExecutableClientPaths()
	if err != nil {
		t.Fatalf("CurrentExecutableClientPaths returned error: %v", err)
	}
	return paths
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
