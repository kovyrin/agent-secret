package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
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
		{name: "executable identity", mutate: func(r *request.ExecRequest) { r.ExecutableIdentity.Inode++ }},
		{name: "cwd", mutate: func(r *request.ExecRequest) { r.CWD = "/tmp/other" }},
		{name: "environment fingerprint", mutate: func(r *request.ExecRequest) {
			r.EnvironmentFingerprint = request.EnvironmentFingerprint([]string{
				"PATH=/opt/homebrew/bin",
				"NODE_OPTIONS=--require ./changed.js",
			})
		}},
		{name: "ref", mutate: func(r *request.ExecRequest) { r.Secrets[0].Ref.Raw = "op://Example Vault/Other/token" }},
		{name: "account", mutate: func(r *request.ExecRequest) { r.Secrets[0].Account = "Fixture" }},
		{name: "delivery mode", mutate: func(r *request.ExecRequest) { r.DeliveryMode = request.DeliverySessionSocket }},
		{name: "override", mutate: func(r *request.ExecRequest) { r.OverrideEnv = true }},
		{name: "overridden alias", mutate: func(r *request.ExecRequest) { r.OverriddenAliases = []string{"TOKEN"} }},
		{name: "mutable executable opt-in", mutate: func(r *request.ExecRequest) { r.AllowMutableExecutable = true }},
		{name: "ttl", mutate: func(r *request.ExecRequest) { r.TTL = 5 * time.Minute }},
		{name: "reusable uses", mutate: func(r *request.ExecRequest) { r.ReusableUses = request.DefaultReusableUses + 1 }},
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

func TestReusableApprovalUsesRequestedUseLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	req.ReusableUses = 2

	approval, err := store.AddReusableWithLimit(req, 2, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusableWithLimit returned error: %v", err)
	}
	if approval.MaxUses != 2 {
		t.Fatalf("max uses = %d, want 2", approval.MaxUses)
	}

	audit := &memoryReuseAudit{}
	if _, err := store.FindReusable(context.Background(), req, audit); err != nil {
		t.Fatalf("FindReusable returned error: %v", err)
	}
	if len(audit.events) != 1 || audit.events[0].RemainingUse != 2 {
		t.Fatalf("unexpected audit events: %+v", audit.events)
	}

	for range 2 {
		if _, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered); err != nil {
			t.Fatalf("FinishReusableAttempt returned error: %v", err)
		}
	}
	if _, err := store.FindReusable(context.Background(), req, nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected two-use approval to be removed, got %v", err)
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
	expired, err := expiredStore.FindReusable(context.Background(), req, nil)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired approval, got %v", err)
	}
	if expired.ID != "expired" {
		t.Fatalf("expired approval id = %q, want expired", expired.ID)
	}
	if _, err := expiredStore.FindReusable(context.Background(), req, nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected expired approval to be removed, got %v", err)
	}
}

func TestFinishReusableAttemptRejectsExpiredApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(req, "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	now = req.ExpiresAt
	expired, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired approval at payload delivery, got %v", err)
	}
	if expired.Uses != 0 {
		t.Fatalf("expired approval consumed use: %d", expired.Uses)
	}
	if _, err := store.FindReusable(context.Background(), req, nil); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected expired approval to be removed, got %v", err)
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
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token", Account: "Fixture"},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	handleID := onlyHandleID(t, session)
	grant, err := store.ResolveHandle(session.ID, handleID, session.Nonce)
	if err != nil {
		t.Fatalf("ResolveHandle returned error: %v", err)
	}
	if grant.Alias != "TOKEN" || grant.Account != "Fixture" {
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

func TestSessionCreationAndLookupFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	if _, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
	}, 0); !errors.Is(err, ErrReadExhausted) {
		t.Fatalf("expected read exhaustion for maxReads=0, got %v", err)
	}

	session, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}
	if _, err := store.ResolveHandle("missing", "handle", "nonce_1"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected missing session mismatch, got %v", err)
	}
	if _, err := store.ResolveHandle(session.ID, "missing", session.Nonce); !errors.Is(err, ErrHandleMissing) {
		t.Fatalf("expected missing handle error, got %v", err)
	}
	if err := store.DestroySession("missing"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected missing destroy mismatch, got %v", err)
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
	if err := cache.Put(approval.ID, req.Secrets[0].Ref.Raw, req.Secrets[0].Account, canarySecret); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if value, ok := cache.Get(approval.ID, req.Secrets[0].Ref.Raw, req.Secrets[0].Account); !ok || value != canarySecret {
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
		{Alias: "TOKEN", Ref: req.Secrets[0].Ref.Raw, Account: req.Secrets[0].Account},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}
	if err := cache.Put(session.ID, req.Secrets[0].Ref.Raw, req.Secrets[0].Account, canarySecret); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	encoded, err = json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if string(encoded) == "" || containsCanary(encoded) {
		t.Fatalf("session object leaked canary: %s", encoded)
	}
}

func TestSecretCacheClearScope(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope_1", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put scope_1 returned error: %v", err)
	}
	if err := cache.Put("scope_2", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put scope_2 returned error: %v", err)
	}
	cache.ClearScope("scope_1")

	if _, ok := cache.Get("scope_1", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_1 value survived ClearScope")
	}
	if value, ok := cache.Get("scope_2", "op://Example/Item/token", ""); !ok || value != "second" {
		t.Fatalf("scope_2 value = %q, %v; want second, true", value, ok)
	}
}

func TestSecretCacheSeparatesSameRefAcrossAccounts(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope", "op://Example/Item/token", "Personal", "personal"); err != nil {
		t.Fatalf("Put Personal returned error: %v", err)
	}
	if err := cache.Put("scope", "op://Example/Item/token", "Work", "work"); err != nil {
		t.Fatalf("Put Work returned error: %v", err)
	}

	if value, ok := cache.Get("scope", "op://Example/Item/token", "Personal"); !ok || value != "personal" {
		t.Fatalf("personal value = %q, %v; want personal, true", value, ok)
	}
	if value, ok := cache.Get("scope", "op://Example/Item/token", "Work"); !ok || value != "work" {
		t.Fatalf("work value = %q, %v; want work, true", value, ok)
	}
}

func TestSecretCacheReplacesValues(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put first returned error: %v", err)
	}
	if err := cache.Put("scope", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put second returned error: %v", err)
	}

	if value, ok := cache.Get("scope", "op://Example/Item/token", ""); !ok || value != "second" {
		t.Fatalf("value = %q, %v; want second, true", value, ok)
	}
}

func TestSecretCacheClearRemovesAllValues(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope_1", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put scope_1 returned error: %v", err)
	}
	if err := cache.Put("scope_2", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put scope_2 returned error: %v", err)
	}
	cache.Clear()

	if _, ok := cache.Get("scope_1", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_1 value survived Clear")
	}
	if _, ok := cache.Get("scope_2", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_2 value survived Clear")
	}
}

func TestUnknownDeliveryResultDoesNotConsumeReusableUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	approval, err := store.AddReusable(testRequest(t, now), "appr_1", "nonce_1")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	after, err := store.FinishReusableAttempt(approval.ID, DeliveryResult("future_result"))
	if err != nil {
		t.Fatalf("FinishReusableAttempt returned error: %v", err)
	}
	if after.Uses != 0 {
		t.Fatalf("unknown delivery result consumed use: %d", after.Uses)
	}
}

func TestAddReusableAndCreateSessionGenerateIdentifiers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	approval, err := store.AddReusable(testRequest(t, now), "", "")
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if !strings.HasPrefix(approval.ID, "appr_") || !strings.HasPrefix(approval.Nonce, "nonce_") {
		t.Fatalf("generated approval identifiers = %+v", approval)
	}
	if len(approval.ID) != len("appr_")+32 || len(approval.Nonce) != len("nonce_")+32 {
		t.Fatalf("generated approval identifier lengths = id:%d nonce:%d", len(approval.ID), len(approval.Nonce))
	}

	session, err := store.CreateSession("", "", now.Add(time.Minute), []SecretGrant{
		{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
	}, 1)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}
	if !strings.HasPrefix(session.ID, "sess_") || !strings.HasPrefix(session.Nonce, "nonce_") {
		t.Fatalf("generated session identifiers = %+v", session)
	}
	if len(session.ID) != len("sess_")+32 || len(session.Nonce) != len("nonce_")+32 {
		t.Fatalf("generated session identifier lengths = id:%d nonce:%d", len(session.ID), len(session.Nonce))
	}
	handleID := onlyHandleID(t, session)
	if !strings.HasPrefix(handleID, "h_") || len(handleID) != len("h_")+32 {
		t.Fatalf("generated handle id = %q", handleID)
	}
}

func TestStoreRandomIDFailuresReturnErrors(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	entropyErr := errors.New("entropy unavailable")
	grants := []SecretGrant{{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"}}
	tests := []struct {
		name string
		run  func(*testing.T, *Store) error
		want string
	}{
		{
			name: "reusable approval id",
			run: func(t *testing.T, store *Store) error {
				t.Helper()
				_, err := store.AddReusable(testRequest(t, now), "", "nonce_1")
				return err
			},
			want: "generate reusable approval id",
		},
		{
			name: "reusable approval nonce",
			run: func(t *testing.T, store *Store) error {
				t.Helper()
				_, err := store.AddReusable(testRequest(t, now), "appr_1", "")
				return err
			},
			want: "generate reusable approval nonce",
		},
		{
			name: "session id",
			run: func(_ *testing.T, store *Store) error {
				_, err := store.CreateSession("", "nonce_1", now.Add(time.Minute), grants, 1)
				return err
			},
			want: "generate session id",
		},
		{
			name: "session nonce",
			run: func(_ *testing.T, store *Store) error {
				_, err := store.CreateSession("sess_1", "", now.Add(time.Minute), grants, 1)
				return err
			},
			want: "generate session nonce",
		},
		{
			name: "secret handle id",
			run: func(_ *testing.T, store *Store) error {
				_, err := store.CreateSession("sess_1", "nonce_1", now.Add(time.Minute), grants, 1)
				return err
			},
			want: "generate secret handle id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewStore(func() time.Time { return now })
			store.random = failingRandomReader{err: entropyErr}
			err := tc.run(t, store)
			if !errors.Is(err, entropyErr) {
				t.Fatalf("expected entropy error, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
		})
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
		ExecutableIdentity: fileidentity.Identity{Device: 1, Inode: 1, Mode: 0o755},
		CWD:                "/tmp/project",
		EnvironmentFingerprint: request.EnvironmentFingerprint([]string{
			"PATH=/opt/homebrew/bin",
			"NODE_OPTIONS=--require ./safe.js",
		}),
		Secrets:      []request.Secret{{Alias: "TOKEN", Ref: ref}},
		TTL:          2 * time.Minute,
		ReceivedAt:   now,
		ExpiresAt:    now.Add(2 * time.Minute),
		DeliveryMode: request.DeliveryEnvExec,
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

type failingRandomReader struct {
	err error
}

func (r failingRandomReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func containsCanary(data []byte) bool {
	return json.Valid(data) && strings.Contains(string(data), canarySecret)
}
