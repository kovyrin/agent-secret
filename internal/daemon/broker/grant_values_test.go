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
		identityForGrantValueTest("op://Vault/Alpha/token", "a.example"),
		identityForGrantValueTest("op://Vault/Alpha/token", "b.example"),
		identityForGrantValueTest("op://Vault/Beta/token", "b.example"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("uniqueSecretIdentities = %+v, want %+v", got, want)
	}
}

func TestPendingIdentitiesPreservesOriginalOrder(t *testing.T) {
	t.Parallel()

	first := identityForGrantValueTest("op://Vault/First/token", "a.example")
	second := identityForGrantValueTest("op://Vault/Second/token", "a.example")
	third := identityForGrantValueTest("op://Vault/Third/token", "a.example")

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

	alpha := identityForGrantValueTest("op://Vault/Alpha/token", "a.example")
	beta := identityForGrantValueTest("op://Vault/Beta/token", "b.example")
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", alpha.ref.Raw, alpha.account),
		secretForGrantValueTest("ALPHA_COPY", alpha.ref.Raw, alpha.account),
		secretForGrantValueTest("BETA", beta.ref.Raw, beta.account),
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

	identity := identityForGrantValueTest("op://Vault/Alpha/token", "a.example")
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", identity.ref.Raw, identity.account),
		secretForGrantValueTest("OTHER", "op://Vault/Other/token", identity.account),
		secretForGrantValueTest("ALPHA_COPY", identity.ref.Raw, identity.account),
	}

	got := auditRefsForIdentity(secrets, identity)
	want := []audit.SecretRef{
		{Alias: "ALPHA", Ref: identity.ref.Raw, Account: identity.account},
		{Alias: "ALPHA_COPY", Ref: identity.ref.Raw, Account: identity.account},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentity = %+v, want %+v", got, want)
	}

	missing := identityForGrantValueTest("op://Vault/Missing/token", "a.example")
	got = auditRefsForIdentity(secrets, missing)
	want = []audit.SecretRef{{Ref: missing.ref.Raw, Account: missing.account}}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentity fallback = %+v, want %+v", got, want)
	}
}

func TestAuditRefsForIdentitiesReturnsMatchedAndFallbackRefs(t *testing.T) {
	t.Parallel()

	alpha := identityForGrantValueTest("op://Vault/Alpha/token", "a.example")
	missing := identityForGrantValueTest("op://Vault/Missing/token", "a.example")
	secrets := []request.Secret{
		secretForGrantValueTest("ALPHA", alpha.ref.Raw, alpha.account),
		secretForGrantValueTest("OTHER", "op://Vault/Other/token", alpha.account),
	}

	got := auditRefsForIdentities(secrets, []secretIdentity{alpha, missing})
	want := []audit.SecretRef{
		{Alias: "ALPHA", Ref: alpha.ref.Raw, Account: alpha.account},
		{Ref: missing.ref.Raw, Account: missing.account},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("auditRefsForIdentities = %+v, want %+v", got, want)
	}
}

func secretForGrantValueTest(alias string, ref string, account string) request.Secret {
	parsed, err := request.ParseSecretRef(ref)
	if err != nil {
		panic(err)
	}
	return request.Secret{
		Alias:   alias,
		Ref:     parsed,
		Account: account,
	}
}

func identityForGrantValueTest(ref string, account string) secretIdentity {
	return identityForSecret(secretForGrantValueTest("", ref, account))
}
