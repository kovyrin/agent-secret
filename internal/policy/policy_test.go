package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
)

const canarySecret = "synthetic-secret-value"

type memoryReuseAudit struct {
	err    error
	events []ReuseAuditEvent
}

func (m *memoryReuseAudit) ApprovalReused(_ context.Context, event ReuseAuditEvent) error {
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, event)
	return nil
}

func TestReusableApprovalMatchesExactRequestAndAuditsBeforeUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)

	approval, err := store.AddReusable(req, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	audit := &memoryReuseAudit{}
	reused, err := store.FindReusable(context.Background(), req, audit)
	if err != nil {
		t.Fatalf("FindReusable returned error: %v", err)
	}
	if reused.ID != approval.ID {
		t.Fatalf("reused approval = %q, want %q", reused.ID, approval.ID)
	}
	if len(audit.events) != 1 || audit.events[0].RemainingUse != DefaultReusableUses {
		t.Fatalf("unexpected audit events: %+v", audit.events)
	}

	after, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered)
	if err != nil {
		t.Fatalf("FinishReusableAttempt returned error: %v", err)
	}
	if after.Uses != 1 {
		t.Fatalf("uses = %d, want 1", after.Uses)
	}
}

func TestReusableApprovalMissesOnPolicyChanges(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	if _, err := store.AddReusable(req, "appr_1", "nonce_1"); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*request.ExecRequest)
	}{
		{name: "reason", mutate: func(r *request.ExecRequest) { r.Reason = "different" }},
		{name: "command shape", mutate: func(r *request.ExecRequest) { r.Command = append(r.Command, "-refresh=false") }},
		{name: "resolved executable", mutate: func(r *request.ExecRequest) { r.ResolvedExecutable = "/different/tool" }},
		{name: "cwd", mutate: func(r *request.ExecRequest) { r.CWD = "/tmp/other" }},
		{name: "ref", mutate: func(r *request.ExecRequest) { r.Secrets[0].Ref.Raw = "op://Example Vault/Other/token" }},
		{name: "delivery mode", mutate: func(r *request.ExecRequest) { r.DeliveryMode = request.DeliverySessionSocket }},
		{name: "override", mutate: func(r *request.ExecRequest) { r.OverrideEnv = true }},
		{name: "overridden alias", mutate: func(r *request.ExecRequest) { r.OverriddenAliases = []string{"TOKEN"} }},
		{name: "ttl", mutate: func(r *request.ExecRequest) { r.TTL = 5 * time.Minute }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := req
			changed.Command = append([]string(nil), req.Command...)
			changed.Secrets = append([]request.Secret(nil), req.Secrets...)
			tt.mutate(&changed)

			_, err := store.FindReusable(context.Background(), changed, nil)
			if !errors.Is(err, ErrMismatch) {
				t.Fatalf("expected mismatch, got %v", err)
			}
		})
	}
}

func TestReusableApprovalDoesNotConsumeUseBeforePayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(req, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	after, err := store.FinishReusableAttempt(approval.ID, DeliveryPrePayloadFailure)
	if err != nil {
		t.Fatalf("FinishReusableAttempt returned error: %v", err)
	}
	if after.Uses != 0 {
		t.Fatalf("pre-payload failure consumed use: %d", after.Uses)
	}
}

func TestReusableApprovalConsumesUseForAllPostPayloadOutcomes(t *testing.T) {
	t.Parallel()

	outcomes := []DeliveryResult{
		DeliveryPayloadDelivered,
		DeliveryCLISpawnFailureAfterPayload,
		DeliveryImmediateChildExitAfterPayload,
		DeliveryNonZeroChildExitAfterPayload,
		DeliveryCommandStartedAuditFailureAfter,
		DeliveryClientDisconnectAfterPayload,
	}

	for _, outcome := range outcomes {
		t.Run(string(outcome), func(t *testing.T) {
			t.Parallel()

			now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
			store := NewStore(func() time.Time { return now })
			approval, err := store.AddReusable(testRequest(t, now), "appr_1", "nonce_1")
			if err != nil {
				t.Fatalf("AddReusable returned error: %v", err)
			}

			after, err := store.FinishReusableAttempt(approval.ID, outcome)
			if err != nil {
				t.Fatalf("FinishReusableAttempt returned error: %v", err)
			}
			if after.Uses != 1 {
				t.Fatalf("uses = %d, want 1", after.Uses)
			}
		})
	}
}

func TestReusableApprovalExpiresAndExhaustsUses(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(req, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	for range DefaultReusableUses {
		if _, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered); err != nil {
			t.Fatalf("FinishReusableAttempt returned error: %v", err)
		}
	}
	if _, err := store.FindReusable(context.Background(), req, nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected exhausted approval to be removed, got %v", err)
	}

	expiredStore := NewStore(func() time.Time { return now.Add(11 * time.Minute) })
	if _, err := expiredStore.AddReusable(req, "expired", "nonce"); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if _, err := expiredStore.FindReusable(context.Background(), req, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired approval, got %v", err)
	}
}

func TestReusableApprovalAuditFailureFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	if _, err := store.AddReusable(req, "appr_1", "nonce_1"); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	_, err := store.FindReusable(context.Background(), req, &memoryReuseAudit{err: errors.New("disk full")})
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("expected audit failure, got %v", err)
	}
}

func TestSessionHandlesEnforceNonceTTLReadsAndDestroy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	session, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	handleID := onlyHandleID(t, session)
	grant, err := store.ResolveHandle(session.ID, handleID, session.Nonce)
	if err != nil {
		t.Fatalf("ResolveHandle returned error: %v", err)
	}
	if grant.Alias != "TOKEN" {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := store.ResolveHandle(session.ID, handleID, session.Nonce); !errors.Is(err, ErrReadExhausted) {
		t.Fatalf("expected read exhaustion, got %v", err)
	}
	if _, err := store.ResolveHandle(session.ID, handleID, "wrong"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
	if err := store.DestroySession(session.ID); err != nil {
		t.Fatalf("DestroySession returned error: %v", err)
	}
	if _, err := store.ResolveHandle(session.ID, handleID, session.Nonce); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("expected destroyed session, got %v", err)
	}
}

func TestSessionExpiration(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now.Add(2 * time.Minute) })
	session, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	if _, err := store.ResolveHandle(session.ID, onlyHandleID(t, session), session.Nonce); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired session, got %v", err)
	}
}

func TestPolicyObjectsAreValueFreeWhenCacheContainsSecret(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(req, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	cache := NewSecretCache()
	cache.Put(approval.ID, req.Secrets[0].Ref.Raw, canarySecret)
	if value, ok := cache.Get(approval.ID, req.Secrets[0].Ref.Raw); !ok || value != canarySecret {
		t.Fatal("secret cache did not return stored canary")
	}

	encoded, err := json.Marshal(approval)
	if err != nil {
		t.Fatalf("marshal approval: %v", err)
	}
	if string(encoded) == "" || containsCanary(encoded) {
		t.Fatalf("policy object leaked canary: %s", encoded)
	}

	session, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: req.Secrets[0].Ref.Raw},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}
	cache.Put(session.ID, req.Secrets[0].Ref.Raw, canarySecret)
	encoded, err = json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if string(encoded) == "" || containsCanary(encoded) {
		t.Fatalf("session object leaked canary: %s", encoded)
	}
}

func testRequest(t *testing.T, now time.Time) request.ExecRequest {
	t.Helper()

	ref, err := request.ParseSecretRef("op://Example Vault/Item/token")
	if err != nil {
		t.Fatalf("ParseSecretRef returned error: %v", err)
	}
	return request.ExecRequest{
		Reason:             "Run Terraform plan",
		Command:            []string{"terraform", "plan"},
		ResolvedExecutable: "/opt/homebrew/bin/terraform",
		CWD:                "/tmp/project",
		Secrets:            []request.Secret{{Alias: "TOKEN", Ref: ref}},
		TTL:                2 * time.Minute,
		ReceivedAt:         now,
		ExpiresAt:          now.Add(2 * time.Minute),
		DeliveryMode:       request.DeliveryEnvExec,
	}
}

func onlyHandleID(t *testing.T, session Session) string {
	t.Helper()

	if len(session.Handles) != 1 {
		t.Fatalf("expected one handle, got %d", len(session.Handles))
	}
	for id := range session.Handles {
		return id
	}
	panic("unreachable")
}

func containsCanary(data []byte) bool {
	return json.Valid(data) && strings.Contains(string(data), canarySecret)
}
