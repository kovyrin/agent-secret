package broker

import (
	"maps"
	"slices"
	"testing"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestUniqueSecretIdentitiesDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()

	secrets := []request.Secret{
		secretForGrantValueTest("SECOND", "op://Vault/Beta/token", "b.example"),
		secretForGrantValueTest("FIRST", "op://Vault/Alpha/token", "b.example"),
		secretForGrantValueTest("ALIAS", "op://Vault/Alpha/token", "a.example"),
		secretForGrantValueTest("FIRST_DUP", "op://Vault/Alpha/token", "b.example"),
	}

	got := uniqueSecretIdentities(secrets)
	want := []secretIdentity{
		{ref: "op://Vault/Alpha/token", account: "a.example"},
		{ref: "op://Vault/Alpha/token", account: "b.example"},
		{ref: "op://Vault/Beta/token", account: "b.example"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("uniqueSecretIdentities = %+v, want %+v", got, want)
	}
}

func TestPendingIdentitiesPreservesOriginalOrder(t *testing.T) {
	t.Parallel()

	first := secretIdentity{ref: "op://Vault/First/token", account: "a.example"}
	second := secretIdentity{ref: "op://Vault/Second/token", account: "a.example"}
	third := secretIdentity{ref: "op://Vault/Third/token", account: "a.example"}

	got := pendingIdentities([]secretIdentity{first, second, third}, map[secretIdentity]struct{}{
		third: {},
		first: {},
	})
	want := []secretIdentity{first, third}
	if !slices.Equal(got, want) {
		t.Fatalf("pendingIdentities = %+v, want %+v", got, want)
	}
}

func TestFanoutValuesMapsAliasesToResolvedIdentityValues(t *testing.T) {
	t.Parallel()

	alpha := secretIdentity{ref: "op://Vault/Alpha/token", account: "a.example"}
	beta := secretIdentity{ref: "op://Vault/Beta/token", account: "b.example"}
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", alpha.ref, alpha.account),
		secretForGrantValueTest("ALPHA_COPY", alpha.ref, alpha.account),
		secretForGrantValueTest("BETA", beta.ref, beta.account),
	}

	got := fanoutValues(secrets, map[secretIdentity]string{
		alpha: "alpha-value",
		beta:  "beta-value",
	})
	want := map[string]string{
		"ALPHA":      "alpha-value",
		"ALPHA_COPY": "alpha-value",
		"BETA":       "beta-value",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("fanoutValues = %+v, want %+v", got, want)
	}
}

func TestAuditRefsForIdentityReturnsAliasesOrFallback(t *testing.T) {
	t.Parallel()

	identity := secretIdentity{ref: "op://Vault/Alpha/token", account: "a.example"}
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", identity.ref, identity.account),
		secretForGrantValueTest("OTHER", "op://Vault/Other/token", identity.account),
		secretForGrantValueTest("ALPHA_COPY", identity.ref, identity.account),
	}

	got := auditRefsForIdentity(secrets, identity)
	want := []audit.SecretRef{
		{Alias: "ALPHA", Ref: identity.ref, Account: identity.account},
		{Alias: "ALPHA_COPY", Ref: identity.ref, Account: identity.account},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentity = %+v, want %+v", got, want)
	}

	missing := secretIdentity{ref: "op://Vault/Missing/token", account: "a.example"}
	got = auditRefsForIdentity(secrets, missing)
	want = []audit.SecretRef{{Ref: missing.ref, Account: missing.account}}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentity fallback = %+v, want %+v", got, want)
	}
}

func TestAuditRefsForIdentitiesReturnsMatchedAndFallbackRefs(t *testing.T) {
	t.Parallel()

	alpha := secretIdentity{ref: "op://Vault/Alpha/token", account: "a.example"}
	missing := secretIdentity{ref: "op://Vault/Missing/token", account: "a.example"}
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", alpha.ref, alpha.account),
		secretForGrantValueTest("OTHER", "op://Vault/Other/token", alpha.account),
	}

	got := auditRefsForIdentities(secrets, []secretIdentity{alpha, missing})
	want := []audit.SecretRef{
		{Alias: "ALPHA", Ref: alpha.ref, Account: alpha.account},
		{Ref: missing.ref, Account: missing.account},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentities = %+v, want %+v", got, want)
	}
}

func secretForGrantValueTest(alias string, ref string, account string) request.Secret {
	return request.Secret{
		Alias:   alias,
		Ref:     request.SecretRef{Raw: ref},
		Account: account,
	}
}
