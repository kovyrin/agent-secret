package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestBrokerSessionCreateResolveConsumesReadAndAuditsCommand(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:      func() time.Time { return now },
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})

	createReq := testSessionCreateRequest(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}}, 1)
	created, err := broker.HandleSessionCreate(context.Background(), testCorrelation("req_create", "nonce_create"), createReq)
	if err != nil {
		t.Fatalf("HandleSessionCreate returned error: %v", err)
	}
	if created.SessionID == "" || created.RemainingReads != 1 {
		t.Fatalf("created session payload = %+v", created)
	}

	peer := testSessionPeer(t, createReq.CWD)
	resolveReq := testSessionResolveRequest(t, created.SessionID, createReq.CWD, peer)
	delivery, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_resolve", "nonce_resolve"), resolveReq, peer)
	if err != nil {
		t.Fatalf("PrepareSessionResolve returned error: %v", err)
	}
	if delivery.Payload().Env["TOKEN"] != "value" {
		t.Fatalf("session env = %+v", delivery.Payload().Env)
	}
	if err := delivery.BeforeWrite(context.Background()); err != nil {
		t.Fatalf("BeforeWrite returned error: %v", err)
	}
	delivery.CommitDelivered()

	if err := broker.ReportStarted(context.Background(), testCorrelation("req_resolve", "nonce_resolve"), 1234); err != nil {
		t.Fatalf("ReportStarted returned error: %v", err)
	}
	if err := broker.ReportCompleted(context.Background(), testCorrelation("req_resolve", "nonce_resolve"), 0, ""); err != nil {
		t.Fatalf("ReportCompleted returned error: %v", err)
	}

	if _, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_again", "nonce_again"), resolveReq, peer); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second PrepareSessionResolve error = %v, want ErrSessionNotFound", err)
	}
	got := auditEventTypes(aud.Events())
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSessionCreated,
		audit.EventSessionResolved,
		audit.EventCommandStarting,
		audit.EventCommandStarted,
		audit.EventCommandCompleted,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
}

func TestBrokerSessionResolveFiltersRequestedAliases(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	specs := []request.SecretSpec{
		{Alias: "A_TOKEN", Ref: "op://Example/Item/a", Account: "Work"},
		{Alias: "B_TOKEN", Ref: "op://Example/Item/b", Account: "Work"},
		{Alias: "C_TOKEN", Ref: "op://Example/Item/c", Account: "Work"},
	}
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:      func() time.Time { return now },
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{
			resolverCallKey("op://Example/Item/a", "Work"): "a-value",
			resolverCallKey("op://Example/Item/b", "Work"): "b-value",
			resolverCallKey("op://Example/Item/c", "Work"): "c-value",
		}},
		Audit: aud,
	})

	createReq := testSessionCreateRequest(t, now, specs, 2)
	created, err := broker.HandleSessionCreate(context.Background(), testCorrelation("req_create", "nonce_create"), createReq)
	if err != nil {
		t.Fatalf("HandleSessionCreate returned error: %v", err)
	}
	if !reflect.DeepEqual(created.SecretAliases, []string{"A_TOKEN", "B_TOKEN", "C_TOKEN"}) {
		t.Fatalf("created secret aliases = %v", created.SecretAliases)
	}

	peer := testSessionPeer(t, createReq.CWD)
	missingReq := testSessionResolveRequest(t, created.SessionID, createReq.CWD, peer)
	missingReq, err = missingReq.WithRequestedAliases([]string{"MISSING_TOKEN"})
	if err != nil {
		t.Fatalf("WithRequestedAliases returned error: %v", err)
	}
	if _, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_missing", "nonce_missing"), missingReq, peer); !errors.Is(err, request.ErrInvalidAlias) {
		t.Fatalf("missing alias PrepareSessionResolve error = %v, want ErrInvalidAlias", err)
	}

	resolveReq := testSessionResolveRequest(t, created.SessionID, createReq.CWD, peer)
	resolveReq, err = resolveReq.WithRequestedAliases([]string{"B_TOKEN", "A_TOKEN"})
	if err != nil {
		t.Fatalf("WithRequestedAliases returned error: %v", err)
	}
	delivery, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_resolve", "nonce_resolve"), resolveReq, peer)
	if err != nil {
		t.Fatalf("PrepareSessionResolve returned error: %v", err)
	}
	payload := delivery.Payload()
	wantAliases := []string{"A_TOKEN", "B_TOKEN"}
	if !reflect.DeepEqual(payload.SecretAliases, wantAliases) {
		t.Fatalf("payload secret aliases = %v, want %v", payload.SecretAliases, wantAliases)
	}
	if !reflect.DeepEqual(payload.Env, map[string]string{"A_TOKEN": "a-value", "B_TOKEN": "b-value"}) {
		t.Fatalf("payload env = %+v", payload.Env)
	}
	if err := delivery.BeforeWrite(context.Background()); err != nil {
		t.Fatalf("BeforeWrite returned error: %v", err)
	}
	delivery.CommitDelivered()

	var resolvedRefs []audit.SecretRef
	var commandRefs []audit.SecretRef
	for _, event := range aud.Events() {
		if event.Type == audit.EventSessionResolved {
			resolvedRefs = event.SecretRefs
		}
		if event.Type == audit.EventCommandStarting {
			commandRefs = event.SecretRefs
		}
	}
	if !reflect.DeepEqual(secretRefAliases(resolvedRefs), wantAliases) {
		t.Fatalf("session_resolved refs = %+v, want aliases %v", resolvedRefs, wantAliases)
	}
	if !reflect.DeepEqual(secretRefAliases(commandRefs), wantAliases) {
		t.Fatalf("command_starting refs = %+v, want aliases %v", commandRefs, wantAliases)
	}
}

func TestBrokerSessionResolveAbortRestoresRead(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	broker := newTestBroker(t, Options{
		Now:      func() time.Time { return now },
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    &memoryAudit{},
	})
	createReq := testSessionCreateRequest(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}}, 1)
	created, err := broker.HandleSessionCreate(context.Background(), testCorrelation("req_create", "nonce_create"), createReq)
	if err != nil {
		t.Fatalf("HandleSessionCreate returned error: %v", err)
	}
	peer := testSessionPeer(t, createReq.CWD)
	resolveReq := testSessionResolveRequest(t, created.SessionID, createReq.CWD, peer)

	first, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_resolve", "nonce_resolve"), resolveReq, peer)
	if err != nil {
		t.Fatalf("first PrepareSessionResolve returned error: %v", err)
	}
	first.AbortBeforePayload()

	second, err := broker.PrepareSessionResolve(context.Background(), testCorrelation("req_retry", "nonce_retry"), resolveReq, peer)
	if err != nil {
		t.Fatalf("second PrepareSessionResolve returned error after abort: %v", err)
	}
	second.AbortBeforePayload()
}

func TestBrokerSessionListAndDestroy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	aud := &memoryAudit{}
	broker := newTestBroker(t, Options{
		Now:      func() time.Time { return now },
		Approver: &mockApprover{decision: approval.Decision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
		Audit:    aud,
	})

	createReq := testSessionCreateRequest(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}}, 2)
	created, err := broker.HandleSessionCreate(context.Background(), testCorrelation("req_create", "nonce_create"), createReq)
	if err != nil {
		t.Fatalf("HandleSessionCreate returned error: %v", err)
	}

	listed, err := broker.HandleSessionList(context.Background())
	if err != nil {
		t.Fatalf("HandleSessionList returned error: %v", err)
	}
	if len(listed.Sessions) != 1 || listed.Sessions[0].SessionID != created.SessionID {
		t.Fatalf("listed sessions = %+v, want created session %s", listed.Sessions, created.SessionID)
	}
	if listed.Sessions[0].RemainingReads != 2 || listed.Sessions[0].SecretAliases[0] != "TOKEN" {
		t.Fatalf("listed session metadata = %+v", listed.Sessions[0])
	}

	destroyed, err := broker.HandleSessionDestroy(context.Background(), request.SessionDestroyRequest{SessionID: created.SessionID})
	if err != nil {
		t.Fatalf("HandleSessionDestroy returned error: %v", err)
	}
	if destroyed.SessionID != created.SessionID || !destroyed.Destroyed {
		t.Fatalf("destroyed payload = %+v", destroyed)
	}
	listed, err = broker.HandleSessionList(context.Background())
	if err != nil {
		t.Fatalf("HandleSessionList after destroy returned error: %v", err)
	}
	if len(listed.Sessions) != 0 {
		t.Fatalf("listed sessions after destroy = %+v, want empty", listed.Sessions)
	}
	if _, err := broker.HandleSessionDestroy(context.Background(), request.SessionDestroyRequest{SessionID: created.SessionID}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second HandleSessionDestroy error = %v, want ErrSessionNotFound", err)
	}

	got := auditEventTypes(aud.Events())
	want := []audit.EventType{
		audit.EventApprovalRequested,
		audit.EventApprovalGranted,
		audit.EventSecretFetchStarted,
		audit.EventSessionCreated,
		audit.EventSessionDestroyed,
		audit.EventSessionDestroyed,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit events = %v, want %v", got, want)
	}
}

func TestBrokerSessionCreateRecordsTerminalApprovalFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	ref := "op://Example/Item/token"
	tests := []struct {
		name     string
		approver approval.Approver
		wantErr  error
		wantType audit.EventType
	}{
		{
			name:     "denied",
			approver: &mockApprover{decision: approval.Decision{Approved: false, DenialReason: approval.DenialReasonComputerLocked}},
			wantType: audit.EventApprovalDenied,
		},
		{
			name:     "expired",
			approver: &mockApprover{err: approval.ErrRequestExpired},
			wantErr:  approval.ErrRequestExpired,
			wantType: audit.EventApprovalTimedOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aud := &memoryAudit{}
			broker := newTestBroker(t, Options{
				Now:      func() time.Time { return now },
				Approver: tt.approver,
				Resolver: &mockResolver{values: map[string]string{resolverCallKey(ref, "Work"): "value"}},
				Audit:    aud,
			})
			createReq := testSessionCreateRequest(t, now, []request.SecretSpec{{Alias: "TOKEN", Ref: ref, Account: "Work"}}, 1)

			_, err := broker.HandleSessionCreate(context.Background(), testCorrelation("req_create", "nonce_create"), createReq)
			if err == nil {
				t.Fatal("HandleSessionCreate unexpectedly succeeded")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("HandleSessionCreate error = %v, want %v", err, tt.wantErr)
			}
			got := auditEventTypes(aud.Events())
			want := []audit.EventType{audit.EventApprovalRequested, tt.wantType}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("audit events = %v, want %v", got, want)
			}
		})
	}
}

func TestSessionStoreListPrunesExpiredAndExhaustedSessions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 9, 0, 0, 0, time.UTC)
	store := newSessionStore(func() time.Time { return now })
	store.sessions["asess_live_b"] = &sessionRecord{
		ID:            "asess_live_b",
		Reason:        "Deploy",
		CWD:           "/tmp/project",
		SecretAliases: []string{"TOKEN"},
		ExpiresAt:     now.Add(time.Minute),
		MaxReads:      2,
		Reads:         1,
	}
	store.sessions["asess_live_a"] = &sessionRecord{
		ID:            "asess_live_a",
		Reason:        "Deploy",
		CWD:           "/tmp/project",
		SecretAliases: []string{"TOKEN"},
		ExpiresAt:     now.Add(time.Minute),
		MaxReads:      2,
	}
	store.sessions["asess_expired"] = &sessionRecord{
		ID:            "asess_expired",
		Reason:        "Deploy",
		CWD:           "/tmp/project",
		SecretAliases: []string{"TOKEN"},
		ExpiresAt:     now,
		MaxReads:      2,
	}
	store.sessions["asess_exhausted"] = &sessionRecord{
		ID:            "asess_exhausted",
		Reason:        "Deploy",
		CWD:           "/tmp/project",
		SecretAliases: []string{"TOKEN"},
		ExpiresAt:     now.Add(time.Minute),
		MaxReads:      1,
		Reads:         1,
	}

	summaries := store.list()
	if len(summaries) != 2 {
		t.Fatalf("list returned %d sessions: %+v", len(summaries), summaries)
	}
	if summaries[0].SessionID != "asess_live_a" || summaries[1].SessionID != "asess_live_b" {
		t.Fatalf("sessions not sorted by id for equal expiry: %+v", summaries)
	}
	if summaries[0].RemainingReads != 2 || summaries[1].RemainingReads != 1 {
		t.Fatalf("remaining reads mismatch: %+v", summaries)
	}
	if _, ok := store.sessions["asess_expired"]; ok {
		t.Fatal("expired session was not pruned")
	}
	if _, ok := store.sessions["asess_exhausted"]; ok {
		t.Fatal("exhausted session was not pruned")
	}
}

func testSessionCreateRequest(
	t *testing.T,
	now time.Time,
	secrets []request.SecretSpec,
	maxReads int,
) request.SessionCreateRequest {
	t.Helper()
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	exe := currentTestExecutable(t)
	identity, err := fileidentity.Capture(exe)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}
	req, err := request.NewSessionCreate(request.SessionCreateOptions{
		Reason:             "Run deploy workflow",
		Command:            []string{"agent-secret", "session", "create"},
		ResolvedExecutable: exe,
		ExecutableIdentity: identity,
		CWD:                cwd,
		Secrets:            secrets,
		TTL:                10 * time.Minute,
		ReceivedAt:         now,
		MaxReads:           maxReads,
	})
	if err != nil {
		t.Fatalf("NewSessionCreate returned error: %v", err)
	}
	return req
}

func testSessionResolveRequest(
	t *testing.T,
	sessionID string,
	cwd string,
	peer peercred.Info,
) request.SessionResolveRequest {
	t.Helper()
	exe := currentTestExecutable(t)
	identity, err := fileidentity.Capture(exe)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}
	req, err := request.NewSessionResolve(
		sessionID,
		[]string{exe, "-test.run=TestBrokerSessionCreateResolveConsumesReadAndAuditsCommand", "--", "child"},
		exe,
		identity,
		cwd,
		request.EnvironmentFingerprint([]string{"PATH=/usr/bin"}),
	)
	if err != nil {
		t.Fatalf("NewSessionResolve returned error: %v", err)
	}
	return req.WithExpectedPeer(peercred.Expected(peer))
}

func testSessionPeer(t *testing.T, cwd string) peercred.Info {
	t.Helper()
	return peercred.Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            os.Getpid(),
		ExecutablePath: currentTestExecutable(t),
		CWD:            cwd,
	}
}

func currentTestExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	return exe
}
