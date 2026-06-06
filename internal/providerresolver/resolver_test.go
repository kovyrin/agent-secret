package providerresolver

import (
	"context"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestResolverRoutesSecretsByProvider(t *testing.T) {
	t.Parallel()

	onePassword := &fakeOnePasswordResolver{value: "op-value"}
	bitwarden := &fakeBitwardenResolver{value: "bws-value"}
	resolver := New(onePassword, bitwarden)

	opSecret := mustParseSecret(t, request.SecretSpec{
		Alias:   "OP_TOKEN",
		Ref:     "op://Example/Item/token",
		Account: "Work",
	})
	opValue, err := resolver.Resolve(context.Background(), opSecret)
	if err != nil {
		t.Fatalf("Resolve 1Password returned error: %v", err)
	}
	if opValue != "op-value" {
		t.Fatalf("1Password value = %q", opValue)
	}
	if onePassword.ref != "op://Example/Item/token" || onePassword.account != "Work" {
		t.Fatalf("1Password call = ref %q account %q", onePassword.ref, onePassword.account)
	}

	bwsSecret := mustParseSecret(t, request.SecretSpec{
		Alias:  "BWS_TOKEN",
		Ref:    "bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		Source: "work",
	})
	bwsValue, err := resolver.Resolve(context.Background(), bwsSecret)
	if err != nil {
		t.Fatalf("Resolve Bitwarden returned error: %v", err)
	}
	if bwsValue != "bws-value" {
		t.Fatalf("Bitwarden value = %q", bwsValue)
	}
	if bitwarden.secret.Ref.Raw != "bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158" {
		t.Fatalf("Bitwarden secret = %+v", bitwarden.secret)
	}
}

func TestResolverDescribeItemUsesOnePassword(t *testing.T) {
	t.Parallel()

	onePassword := &fakeOnePasswordResolver{
		metadata: itemmetadata.Metadata{Account: "Work", Vault: "Example", Item: "Deploy"},
	}
	resolver := New(onePassword, nil)

	metadata, err := resolver.DescribeItem(context.Background(), itemmetadata.Ref{
		Raw:   "op://Example/Deploy",
		Vault: "Example",
		Item:  "Deploy",
	}, "Work")
	if err != nil {
		t.Fatalf("DescribeItem returned error: %v", err)
	}
	if metadata.Item != "Deploy" || onePassword.describeAccount != "Work" {
		t.Fatalf("metadata = %+v describe account = %q", metadata, onePassword.describeAccount)
	}
}

func TestResolverReportsUnavailableAndUnsupportedProviders(t *testing.T) {
	t.Parallel()

	opSecret := mustParseSecret(t, request.SecretSpec{
		Alias:   "OP_TOKEN",
		Ref:     "op://Example/Item/token",
		Account: "Work",
	})
	if _, err := New(nil, nil).Resolve(context.Background(), opSecret); err == nil {
		t.Fatal("expected unavailable 1Password resolver error")
	}
	if _, err := New(nil, nil).DescribeItem(context.Background(), itemmetadata.Ref{}, "Work"); err == nil {
		t.Fatal("expected unavailable describe resolver error")
	}

	bwsSecret := mustParseSecret(t, request.SecretSpec{
		Alias:  "BWS_TOKEN",
		Ref:    "bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		Source: "work",
	})
	if _, err := New(nil, nil).Resolve(context.Background(), bwsSecret); err == nil {
		t.Fatal("expected unavailable Bitwarden resolver error")
	}

	unknownSecret := request.Secret{
		Alias: "TOKEN",
		Ref: request.SecretRef{
			Raw:      "vault://example",
			Provider: "vault",
		},
	}
	_, err := New(nil, nil).Resolve(context.Background(), unknownSecret)
	if err == nil || !strings.Contains(err.Error(), "unsupported secret provider") {
		t.Fatalf("unsupported provider error = %v", err)
	}
}

func mustParseSecret(t *testing.T, spec request.SecretSpec) request.Secret {
	t.Helper()

	secrets, err := request.ParseSecrets([]request.SecretSpec{spec})
	if err != nil {
		t.Fatalf("ParseSecrets returned error: %v", err)
	}
	return secrets[0]
}

type fakeOnePasswordResolver struct {
	value           string
	ref             string
	account         string
	describeAccount string
	metadata        itemmetadata.Metadata
}

func (r *fakeOnePasswordResolver) Resolve(_ context.Context, ref string, account string) (string, error) {
	r.ref = ref
	r.account = account
	return r.value, nil
}

func (r *fakeOnePasswordResolver) DescribeItem(
	_ context.Context,
	_ itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	r.describeAccount = account
	return r.metadata, nil
}

type fakeBitwardenResolver struct {
	value  string
	secret request.Secret
}

func (r *fakeBitwardenResolver) ResolveSecret(_ context.Context, secret request.Secret) (string, error) {
	r.secret = secret
	return r.value, nil
}
