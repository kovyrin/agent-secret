package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/request"
)

const canarySecret = "synthetic-secret-value"

func TestReusableApprovalMatchesExactRequestAndReturnsReuseMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)

	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	reused, metadata, err := store.MatchReusable(req)
	if err != nil {
		t.Fatalf("MatchReusable returned error: %v", err)
	}
	if reused.ID != approval.ID {
		t.Fatalf("reused approval = %q, want %q", reused.ID, approval.ID)
	}
	if metadata.ApprovalID != approval.ID || metadata.RemainingUses != DefaultReusableUses {
		t.Fatalf("unexpected reuse metadata: %+v", metadata)
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
	if _, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"}); err != nil {
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
		{name: "override", mutate: func(r *request.ExecRequest) { r.OverrideEnv = true }},
		{name: "overridden alias", mutate: func(r *request.ExecRequest) { r.OverriddenAliases = []string{"TOKEN"} }},
		{name: "ttl", mutate: func(r *request.ExecRequest) { r.TTL = 5 * time.Minute }},
		{name: "reusable uses", mutate: func(r *request.ExecRequest) { r.ReusableUses = request.DefaultReusableUses + 1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := req
			changed.Command = append([]string(nil), req.Command...)
			changed.Secrets = append([]request.Secret(nil), req.Secrets...)
			tt.mutate(&changed)

			_, _, err := store.MatchReusable(changed)
			if !errors.Is(err, ErrMismatch) {
				t.Fatalf("expected mismatch, got %v", err)
			}
		})
	}
}

func TestNewReuseKeyIncludesBitwardenSourceMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	req := testRequest(t, now)
	req.Secrets = []request.Secret{
		mustParsePolicySecret(t, request.SecretSpec{
			Alias:     "Z_TOKEN",
			Ref:       "bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
			Bitwarden: request.BitwardenSource{TokenAlias: "work-token"},
		}),
		mustParsePolicySecret(t, request.SecretSpec{
			Alias:     "A_TOKEN",
			Ref:       "bws://personal/be8e0ad8-d545-4017-a55a-b02f014d4158",
			Bitwarden: request.BitwardenSource{TokenAlias: "personal-token"},
		}),
	}

	key := NewReuseKey(req)
	if key.Secrets[0].Alias != "A_TOKEN" || key.Secrets[1].Alias != "Z_TOKEN" {
		t.Fatalf("secrets were not sorted in reuse key: %+v", key.Secrets)
	}
	if key.Secrets[1].Source != "work" ||
		key.Secrets[1].BitwardenTokenAlias != "work-token" {
		t.Fatalf("Bitwarden source metadata missing from reuse key: %+v", key.Secrets[1])
	}

	reordered := req
	reordered.Secrets = append([]request.Secret(nil), req.Secrets[1], req.Secrets[0])
	if !key.Equal(NewReuseKey(reordered)) {
		t.Fatal("reuse key changed when secrets were reordered")
	}

	changed := req
	changed.Secrets = append([]request.Secret(nil), req.Secrets...)
	changed.Secrets[0].Bitwarden.TokenAlias = "other-token"
	if key.Equal(NewReuseKey(changed)) {
		t.Fatal("reuse key ignored Bitwarden token alias change")
	}
}

func TestReusableApprovalUsesRequestedUseLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	req.ReusableUses = 2

	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1", MaxUses: 2})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if approval.MaxUses != 2 {
		t.Fatalf("max uses = %d, want 2", approval.MaxUses)
	}

	_, metadata, err := store.MatchReusable(req)
	if err != nil {
		t.Fatalf("MatchReusable returned error: %v", err)
	}
	if metadata.RemainingUses != 2 {
		t.Fatalf("remaining uses metadata = %d, want 2", metadata.RemainingUses)
	}

	for range 2 {
		if _, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered); err != nil {
			t.Fatalf("FinishReusableAttempt returned error: %v", err)
		}
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected two-use approval to be removed, got %v", err)
	}
}

func TestStoreRemoveReusableAndClear(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	if _, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"}); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if !store.RemoveReusable("appr_1") {
		t.Fatal("RemoveReusable returned false for existing approval")
	}
	if store.RemoveReusable("appr_1") {
		t.Fatal("RemoveReusable returned true for missing approval")
	}

	if _, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_2", Nonce: "nonce_2"}); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	store.Clear()
	if _, _, err := store.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("MatchReusable after Clear = %v, want ErrMismatch", err)
	}
}

func TestReusableApprovalDoesNotConsumeUseBeforePayload(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"})
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

func TestReusableApprovalReservationsBlockConcurrentDelivery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	req.ReusableUses = 1
	approval, err := store.AddReusable(ReusableApprovalSpec{
		Request:      req,
		ID:           "appr_1",
		Nonce:        "nonce_1",
		MaxUses:      1,
		ReservedUses: 1,
	})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if approval.ReservedUses != 1 {
		t.Fatalf("reserved uses = %d, want 1", approval.ReservedUses)
	}

	blocked, _, err := store.ReserveReusable(req)
	if !errors.Is(err, ErrUseExhausted) {
		t.Fatalf("expected reservation to exhaust available delivery slots, got %v", err)
	}
	if blocked.ID != "" {
		t.Fatalf("ReserveReusable returned normal approval on exhausted error: %+v", blocked)
	}
	blockedSnapshot, ok := ReusableApprovalFromError(err)
	if !ok {
		t.Fatalf("exhausted reservation error did not carry approval snapshot: %v", err)
	}
	if blockedSnapshot.ID != approval.ID {
		t.Fatalf("blocked approval id = %q, want %q", blockedSnapshot.ID, approval.ID)
	}

	afterFailure, err := store.FinishReusableAttempt(approval.ID, DeliveryPrePayloadFailure)
	if err != nil {
		t.Fatalf("FinishReusableAttempt after pre-payload failure returned error: %v", err)
	}
	if afterFailure.Uses != 0 || afterFailure.ReservedUses != 0 {
		t.Fatalf("after pre-payload failure = uses:%d reserved:%d, want uses:0 reserved:0", afterFailure.Uses, afterFailure.ReservedUses)
	}

	retry, _, err := store.ReserveReusable(req)
	if err != nil {
		t.Fatalf("ReserveReusable after release returned error: %v", err)
	}
	if retry.ReservedUses != 1 {
		t.Fatalf("retry reserved uses = %d, want 1", retry.ReservedUses)
	}

	afterDelivery, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered)
	if err != nil {
		t.Fatalf("FinishReusableAttempt after payload returned error: %v", err)
	}
	if afterDelivery.Uses != 1 || afterDelivery.ReservedUses != 0 {
		t.Fatalf("after payload delivery = uses:%d reserved:%d, want uses:1 reserved:0", afterDelivery.Uses, afterDelivery.ReservedUses)
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected delivered one-use approval to be removed, got %v", err)
	}
}

func TestFinishReusableAttemptRejectsInvalidDeliveryResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(ReusableApprovalSpec{
		Request:      req,
		ID:           "appr_1",
		Nonce:        "nonce_1",
		ReservedUses: 1,
	})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	_, err = store.FinishReusableAttempt(approval.ID, DeliveryResult("unknown"))
	if !errors.Is(err, ErrInvalidDeliveryResult) {
		t.Fatalf("FinishReusableAttempt invalid result error = %v, want invalid delivery result", err)
	}

	afterFailure, err := store.FinishReusableAttempt(approval.ID, DeliveryPrePayloadFailure)
	if err != nil {
		t.Fatalf("FinishReusableAttempt after invalid result returned error: %v", err)
	}
	if afterFailure.Uses != 0 || afterFailure.ReservedUses != 0 {
		t.Fatalf("after invalid result then release = uses:%d reserved:%d, want uses:0 reserved:0", afterFailure.Uses, afterFailure.ReservedUses)
	}
}

func TestReusableApprovalExpiresAndExhaustsUses(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	for range DefaultReusableUses {
		if _, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered); err != nil {
			t.Fatalf("FinishReusableAttempt returned error: %v", err)
		}
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected exhausted approval to be removed, got %v", err)
	}

	expiredStore := NewStore(func() time.Time { return now.Add(11 * time.Minute) })
	if _, err := expiredStore.AddReusable(ReusableApprovalSpec{Request: req, ID: "expired", Nonce: "nonce"}); err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	expired, _, err := expiredStore.MatchReusable(req)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired approval, got %v", err)
	}
	if expired.ID != "" {
		t.Fatalf("MatchReusable returned normal approval on expired error: %+v", expired)
	}
	expiredSnapshot, ok := ReusableApprovalFromError(err)
	if !ok {
		t.Fatalf("expired reusable error did not carry approval snapshot: %v", err)
	}
	if expiredSnapshot.ID != "expired" {
		t.Fatalf("expired approval id = %q, want expired", expiredSnapshot.ID)
	}
	if _, _, err := expiredStore.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected expired approval to be removed, got %v", err)
	}
}

func TestFinishReusableAttemptRejectsExpiredApproval(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	now = req.ExpiresAt
	expired, err := store.FinishReusableAttempt(approval.ID, DeliveryPayloadDelivered)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired approval at payload delivery, got %v", err)
	}
	if expired.ID != "" {
		t.Fatalf("FinishReusableAttempt returned normal approval on expired error: %+v", expired)
	}
	expiredSnapshot, ok := ReusableApprovalFromError(err)
	if !ok {
		t.Fatalf("expired finish error did not carry approval snapshot: %v", err)
	}
	if expiredSnapshot.Uses != 0 {
		t.Fatalf("expired approval consumed use: %d", expiredSnapshot.Uses)
	}
	if _, _, err := store.MatchReusable(req); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected expired approval to be removed, got %v", err)
	}
}

func TestPolicyObjectsAreValueFree(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	req := testRequest(t, now)
	approval, err := store.AddReusable(ReusableApprovalSpec{Request: req, ID: "appr_1", Nonce: "nonce_1"})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}

	encoded, err := json.Marshal(approval)
	if err != nil {
		t.Fatalf("marshal approval: %v", err)
	}
	if string(encoded) == "" || containsCanary(encoded) {
		t.Fatalf("policy object leaked canary: %s", encoded)
	}
}

func TestAddReusableGeneratesIdentifiers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	store := NewStore(func() time.Time { return now })
	approval, err := store.AddReusable(ReusableApprovalSpec{Request: testRequest(t, now)})
	if err != nil {
		t.Fatalf("AddReusable returned error: %v", err)
	}
	if !strings.HasPrefix(approval.ID, "appr_") || !strings.HasPrefix(approval.Nonce, "nonce_") {
		t.Fatalf("generated approval identifiers = %+v", approval)
	}
	if len(approval.ID) != len("appr_")+32 || len(approval.Nonce) != len("nonce_")+32 {
		t.Fatalf("generated approval identifier lengths = id:%d nonce:%d", len(approval.ID), len(approval.Nonce))
	}
}

func TestStoreRandomIDFailuresReturnErrors(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	entropyErr := errors.New("entropy unavailable")
	tests := []struct {
		name string
		run  func(*testing.T, *Store) error
		want string
	}{
		{
			name: "reusable approval id",
			run: func(t *testing.T, store *Store) error {
				t.Helper()
				_, err := store.AddReusable(ReusableApprovalSpec{Request: testRequest(t, now), Nonce: "nonce_1"})
				return err
			},
			want: "generate reusable approval id",
		},
		{
			name: "reusable approval nonce",
			run: func(t *testing.T, store *Store) error {
				t.Helper()
				_, err := store.AddReusable(ReusableApprovalSpec{Request: testRequest(t, now), ID: "appr_1"})
				return err
			},
			want: "generate reusable approval nonce",
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
		Secrets:    []request.Secret{{Alias: "TOKEN", Ref: ref}},
		TTL:        2 * time.Minute,
		ReceivedAt: now,
		ExpiresAt:  now.Add(2 * time.Minute),
	}
}

func mustParsePolicySecret(t *testing.T, spec request.SecretSpec) request.Secret {
	t.Helper()

	secrets, err := request.ParseSecrets([]request.SecretSpec{spec})
	if err != nil {
		t.Fatalf("ParseSecrets returned error: %v", err)
	}
	return secrets[0]
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
