package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/gcpcompat"
	"github.com/kovyrin/agent-secret/internal/request"
)

type fakeGCPMinter struct {
	tokens []gcpcompat.Token
	calls  []GCPMintRequest
	err    error
}

func (m *fakeGCPMinter) MintAccessToken(_ context.Context, req GCPMintRequest) (gcpcompat.Token, error) {
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

func TestBrokerGCPExecMintsTokenFileAndCleansUpOnCompletion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	minter := &fakeGCPMinter{tokens: []gcpcompat.Token{{AccessToken: "synthetic-gcp-token", ExpiresAt: now.Add(2 * time.Minute)}}}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     minter,
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              aud,
	})
	correlation := testCorrelation("req_gcp", "nonce_gcp")
	req := testGCPExecRequest(now)
	delivery, err := broker.PrepareGCPExecDelivery(context.Background(), correlation, req)
	if err != nil {
		t.Fatalf("PrepareGCPExecDelivery returned error: %v", err)
	}
	payload := delivery.Payload()
	tokenPath := payload.Env[gcpcompat.EnvCloudSDKAccessTokenFile]
	if tokenPath == "" {
		t.Fatalf("payload missing token file env: %+v", payload.Env)
	}
	if data, err := os.ReadFile(tokenPath); err != nil || string(data) != "synthetic-gcp-token" { //nolint:gosec // G304: test reads broker-created token file under t.TempDir.
		t.Fatalf("token file = %q err=%v", string(data), err)
	}
	delivery.CommitDelivered()
	if err := broker.ReportStarted(context.Background(), correlation, 1234); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := broker.ReportCompleted(context.Background(), correlation, 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error: %v", err)
	}
	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file survived completion: %v", err)
	}
	if len(minter.calls) != 1 {
		t.Fatalf("minter calls = %d, want 1", len(minter.calls))
	}
	if minter.calls[0].ServiceAccount != req.ServiceAccount || minter.calls[0].Project != req.Project {
		t.Fatalf("minter request = %+v, want req access", minter.calls[0])
	}
	if !containsAuditEvent(aud.Events(), audit.EventGCPTokenMintStarted) ||
		!containsAuditEvent(aud.Events(), audit.EventGCPTokenMintCompleted) ||
		!containsAuditEvent(aud.Events(), audit.EventCommandCompleted) {
		t.Fatalf("GCP audit events missing: %+v", aud.Events())
	}
}

func TestBrokerGCPSessionReusesTokenThenRefreshesNearMargin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	currentNow := now
	minter := &fakeGCPMinter{tokens: []gcpcompat.Token{
		{AccessToken: "first-token", ExpiresAt: now.Add(10 * time.Minute)},
		{AccessToken: "second-token", ExpiresAt: now.Add(20 * time.Minute)},
	}}
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return currentNow },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     minter,
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              &memoryAudit{},
	})
	createReq := testGCPSessionCreateRequest(now)
	if _, err := broker.CreateGCPSession(context.Background(), testCorrelation("req_create", "nonce_create"), createReq, "asess_test"); err != nil {
		t.Fatalf("CreateGCPSession returned error: %v", err)
	}

	first, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_1", "nonce_1"), testGCPSessionUseRequest("/tmp/project"))
	if err != nil {
		t.Fatalf("first PrepareGCPSessionCommandDelivery returned error: %v", err)
	}
	firstTokenPath := first.Payload().Env[gcpcompat.EnvCloudSDKAccessTokenFile]
	first.CommitDelivered()

	second, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_2", "nonce_2"), testGCPSessionUseRequest("/tmp/project/subdir"))
	if err != nil {
		t.Fatalf("second PrepareGCPSessionCommandDelivery returned error: %v", err)
	}
	if second.Payload().Env[gcpcompat.EnvCloudSDKAccessTokenFile] != firstTokenPath {
		t.Fatalf("session did not reuse token file")
	}
	second.CommitDelivered()

	currentNow = now.Add(9 * time.Minute)
	third, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_3", "nonce_3"), testGCPSessionUseRequest("/tmp/project"))
	if err != nil {
		t.Fatalf("third PrepareGCPSessionCommandDelivery returned error: %v", err)
	}
	if third.Payload().Env[gcpcompat.EnvCloudSDKAccessTokenFile] == firstTokenPath {
		t.Fatalf("session did not refresh token near margin")
	}
	third.CommitDelivered()
	if len(minter.calls) != 2 {
		t.Fatalf("minter calls = %d, want 2", len(minter.calls))
	}
}

func TestBrokerGCPSessionRejectsUseOutsideProjectRoot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     &fakeGCPMinter{},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              &memoryAudit{},
	})
	if _, err := broker.CreateGCPSession(context.Background(), testCorrelation("req_create", "nonce_create"), testGCPSessionCreateRequest(now), "asess_test"); err != nil {
		t.Fatalf("CreateGCPSession returned error: %v", err)
	}
	_, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use", "nonce_use"), testGCPSessionUseRequest("/tmp/other"))
	if !errors.Is(err, ErrGCPSessionNotUsableFromCWD) {
		t.Fatalf("PrepareGCPSessionCommandDelivery error = %v, want cwd rejection", err)
	}
}

func TestBrokerGCPExecDenialStopsBeforeMint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	minter := &fakeGCPMinter{}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: false, DenialReason: "no"}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     minter,
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              aud,
	})
	_, err := broker.PrepareGCPExecDelivery(context.Background(), testCorrelation("req_gcp", "nonce_gcp"), testGCPExecRequest(now))
	if !errors.Is(err, approval.ErrApprovalDenied) {
		t.Fatalf("PrepareGCPExecDelivery error = %v, want approval denied", err)
	}
	if len(minter.calls) != 0 {
		t.Fatalf("minter calls = %d, want 0", len(minter.calls))
	}
	if !containsAuditEvent(aud.Events(), audit.EventApprovalDenied) ||
		containsAuditEvent(aud.Events(), audit.EventGCPTokenMintStarted) {
		t.Fatalf("unexpected denial audit events: %+v", aud.Events())
	}
}

func TestBrokerGCPExecReportsUnavailableMinterAndCleansActiveState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              aud,
	})
	correlation := testCorrelation("req_gcp", "nonce_gcp")
	_, err := broker.PrepareGCPExecDelivery(context.Background(), correlation, testGCPExecRequest(now))
	if !errors.Is(err, ErrNoGCPTokenMinter) {
		t.Fatalf("PrepareGCPExecDelivery error = %v, want minter unavailable", err)
	}
	if broker.ActiveCount() != 0 {
		t.Fatalf("active requests = %d, want 0", broker.ActiveCount())
	}
	if !containsAuditEvent(aud.Events(), audit.EventGCPTokenMintFailed) {
		t.Fatalf("mint failure audit missing: %+v", aud.Events())
	}
}

func TestBrokerGCPExecAbortBeforePayloadCleansTokenAndActiveRequest(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     &fakeGCPMinter{tokens: []gcpcompat.Token{{AccessToken: "synthetic-gcp-token", ExpiresAt: now.Add(2 * time.Minute)}}},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              &memoryAudit{},
	})
	correlation := testCorrelation("req_gcp", "nonce_gcp")
	delivery, err := broker.PrepareGCPExecDelivery(context.Background(), correlation, testGCPExecRequest(now))
	if err != nil {
		t.Fatalf("PrepareGCPExecDelivery returned error: %v", err)
	}
	tokenPath := delivery.Payload().Env[gcpcompat.EnvCloudSDKAccessTokenFile]
	delivery.AbortBeforePayload()
	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token path survived abort: %v", err)
	}
	if _, err := broker.activeRequest(correlation); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("active request after abort = %v, want unknown", err)
	}
}

func TestBrokerGCPSessionListAndDestroy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     &fakeGCPMinter{},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              aud,
	})
	createReq := testGCPSessionCreateRequest(now)
	created, err := broker.CreateGCPSession(context.Background(), testCorrelation("req_create", "nonce_create"), createReq, "asess_test")
	if err != nil {
		t.Fatalf("CreateGCPSession returned error: %v", err)
	}
	listed, err := broker.ListGCPSessions(context.Background(), "/tmp/project")
	if err != nil {
		t.Fatalf("ListGCPSessions returned error: %v", err)
	}
	if len(listed.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %+v", len(listed.Sessions), listed.Sessions)
	}
	session := listed.Sessions[0]
	if session.SessionAuditID != created.SessionAuditID ||
		!session.UsableFromCWD ||
		session.RemainingCommandStarts != createReq.MaxCommandStarts ||
		session.Project != createReq.Project {
		t.Fatalf("unexpected session info: %+v", session)
	}
	outside, err := broker.ListGCPSessions(context.Background(), "/tmp/other")
	if err != nil {
		t.Fatalf("outside ListGCPSessions returned error: %v", err)
	}
	if len(outside.Sessions) != 1 || outside.Sessions[0].UsableFromCWD {
		t.Fatalf("outside session usability = %+v", outside.Sessions)
	}

	destroyed, err := broker.DestroyGCPSession(context.Background(), request.GCPSessionDestroyRequest{SessionHandle: "asess_test", CWD: "/tmp/project"})
	if err != nil {
		t.Fatalf("DestroyGCPSession returned error: %v", err)
	}
	if !destroyed.Destroyed || destroyed.SessionAuditID != created.SessionAuditID {
		t.Fatalf("destroy response = %+v", destroyed)
	}
	again, err := broker.DestroyGCPSession(context.Background(), request.GCPSessionDestroyRequest{SessionHandle: "asess_test", CWD: "/tmp/project"})
	if err != nil {
		t.Fatalf("second DestroyGCPSession returned error: %v", err)
	}
	if again.Destroyed || again.SessionAuditID != "" {
		t.Fatalf("second destroy response = %+v, want not found", again)
	}
	if !containsAuditEvent(aud.Events(), audit.EventGCPSessionDestroyed) {
		t.Fatalf("session destroyed audit missing: %+v", aud.Events())
	}
}

func TestBrokerGCPSessionUseRestoresStartOnAbortAndExhaustsAfterCommit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return now },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     &fakeGCPMinter{},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              &memoryAudit{},
	})
	createReq := testGCPSessionCreateRequest(now)
	createReq.MaxCommandStarts = 1
	if _, err := broker.CreateGCPSession(context.Background(), testCorrelation("req_create", "nonce_create"), createReq, "asess_test"); err != nil {
		t.Fatalf("CreateGCPSession returned error: %v", err)
	}

	first, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_1", "nonce_1"), testGCPSessionUseRequest("/tmp/project"))
	if err != nil {
		t.Fatalf("first PrepareGCPSessionCommandDelivery returned error: %v", err)
	}
	first.AbortBeforePayload()

	second, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_2", "nonce_2"), testGCPSessionUseRequest("/tmp/project"))
	if err != nil {
		t.Fatalf("second PrepareGCPSessionCommandDelivery returned error after abort: %v", err)
	}
	second.CommitDelivered()

	_, err = broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_3", "nonce_3"), testGCPSessionUseRequest("/tmp/project"))
	if !errors.Is(err, ErrGCPSessionExhausted) {
		t.Fatalf("third PrepareGCPSessionCommandDelivery error = %v, want exhausted", err)
	}
}

func TestBrokerGCPSessionExpiredDeletesSession(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	currentNow := now
	broker := newTestBroker(t, Options{
		Now:                func() time.Time { return currentNow },
		Approver:           &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver:           &mockResolver{},
		GCPTokenMinter:     &fakeGCPMinter{},
		GCPDeliveryBaseDir: filepath.Join(t.TempDir(), "gcp"),
		Audit:              &memoryAudit{},
	})
	createReq := testGCPSessionCreateRequest(now)
	if _, err := broker.CreateGCPSession(context.Background(), testCorrelation("req_create", "nonce_create"), createReq, "asess_test"); err != nil {
		t.Fatalf("CreateGCPSession returned error: %v", err)
	}
	currentNow = createReq.ExpiresAt
	_, err := broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use", "nonce_use"), testGCPSessionUseRequest("/tmp/project"))
	if !errors.Is(err, ErrGCPSessionExpired) {
		t.Fatalf("PrepareGCPSessionCommandDelivery error = %v, want expired", err)
	}
	_, err = broker.PrepareGCPSessionCommandDelivery(context.Background(), testCorrelation("req_use_2", "nonce_2"), testGCPSessionUseRequest("/tmp/project"))
	if !errors.Is(err, ErrUnknownGCPSession) {
		t.Fatalf("second PrepareGCPSessionCommandDelivery error = %v, want unknown", err)
	}
}

func testGCPExecRequest(now time.Time) request.GCPExecRequest {
	return request.GCPExecRequest{
		Reason:                 "Inspect logs",
		Command:                []string{"gcloud", "logging", "read", "severity>=ERROR"},
		ResolvedExecutable:     "/usr/bin/gcloud",
		ExecutableIdentity:     fileidentity.Identity{Device: 1, Inode: 2, Mode: 0o755},
		CWD:                    "/tmp/project",
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=/usr/bin"}),
		GoogleAccount:          "work",
		Project:                "fixture-beta",
		ServiceAccount:         "agent-beta-logs@fixture-beta.iam.gserviceaccount.com",
		Scopes:                 []string{"https://www.googleapis.com/auth/cloud-platform"},
		ProfileName:            "beta-logs",
		ConfigRoot:             "/tmp/project",
		DeliveryMode:           request.GCPDeliveryModeTokenFile,
		TTL:                    2 * time.Minute,
		ReceivedAt:             now,
		ExpiresAt:              now.Add(2 * time.Minute),
	}
}

func testGCPSessionCreateRequest(now time.Time) request.GCPSessionCreateRequest {
	return request.GCPSessionCreateRequest{
		Reason:           "Run benchmark",
		GoogleAccount:    "work",
		Project:          "fixture-prod",
		ServiceAccount:   "agent-bench@fixture-prod.iam.gserviceaccount.com",
		Scopes:           []string{"https://www.googleapis.com/auth/cloud-platform"},
		ProfileName:      "fixture-prod-benchmark-run",
		ConfigSourcePath: "/tmp/project/agent-secret.yml",
		ProjectRoot:      "/tmp/project",
		DeliveryMode:     request.GCPDeliveryModeTokenFile,
		TTL:              30 * time.Minute,
		ReceivedAt:       now,
		ExpiresAt:        now.Add(30 * time.Minute),
		MaxCommandStarts: 4,
	}
}

func testGCPSessionUseRequest(cwd string) request.GCPSessionUseRequest {
	return request.GCPSessionUseRequest{
		SessionHandle:          "asess_test",
		Command:                []string{"gcloud", "compute", "instances", "list"},
		ResolvedExecutable:     "/usr/bin/gcloud",
		ExecutableIdentity:     fileidentity.Identity{Device: 1, Inode: 2, Mode: 0o755},
		CWD:                    cwd,
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{"PATH=/usr/bin"}),
	}
}

var _ GCPTokenMinter = (*fakeGCPMinter)(nil)
