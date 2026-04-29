package opresolver

import (
	"context"
	"errors"
	"testing"
)

type fakeSecretsAPI struct {
	value string
	ref   string
	err   error
	calls int
}

func (f *fakeSecretsAPI) Resolve(_ context.Context, ref string) (string, error) {
	f.calls++
	f.ref = ref
	if f.err != nil {
		return "", f.err
	}

	return f.value, nil
}

func TestValidateReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{name: "field", ref: "op://Example Vault/Item/password"},
		{name: "section field", ref: "op://Example Vault/Item/API/token"},
		{name: "missing scheme", ref: "Example Vault/Item/password", wantErr: true},
		{name: "blank segment", ref: "op://Example Vault//password", wantErr: true},
		{name: "too short", ref: "op://Example Vault/Item", wantErr: true},
		{name: "too long", ref: "op://Example Vault/Item/Section/Field/extra", wantErr: true},
		{name: "trimmed", ref: " op://Example Vault/Item/password", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateReference(tt.ref)
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected valid reference, got %v", err)
			}
		})
	}
}

func TestResolveReturnsValueWithoutLoggingIt(t *testing.T) {
	t.Parallel()

	const canary = "synthetic-secret-value"
	fake := &fakeSecretsAPI{value: canary}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	secret, err := resolver.Resolve(context.Background(), "op://Example Vault/Item/password")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if secret.Value() != canary {
		t.Fatal("resolved value did not match fake secret")
	}
	if fake.ref != "op://Example Vault/Item/password" {
		t.Fatalf("resolved unexpected ref: %q", fake.ref)
	}

	metadata := secret.Metadata()
	if metadata.Length != len(canary) {
		t.Fatalf("metadata length = %d, want %d", metadata.Length, len(canary))
	}
	if metadata.SHA256 == "" || metadata.SHA256 == canary {
		t.Fatal("metadata hash was not populated safely")
	}
}

func TestResolveWrapsSDKError(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{err: errors.New("locked")}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), "op://Example Vault/Item/password")
	if err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestNewResolverRequiresSecretsAPI(t *testing.T) {
	t.Parallel()

	_, err := NewResolver(nil)
	if err == nil {
		t.Fatal("expected nil secrets API error")
	}
}

func TestResolveRejectsInvalidReferenceBeforeSDKCall(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{value: "synthetic-secret-value"}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), "Example Vault/Item/password")
	if !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("expected invalid reference error, got %v", err)
	}
	if fake.calls != 0 {
		t.Fatalf("invalid reference called SDK %d time(s)", fake.calls)
	}
}

func TestNormalizeDesktopOptionsAllowsDefaultAccount(t *testing.T) {
	t.Parallel()

	opts := normalizeDesktopOptions(ClientOptions{Account: " \t "})
	if opts.Account != "" {
		t.Fatalf("account = %q, want default account sentinel", opts.Account)
	}
}

func TestDesktopAccountUsesExplicitOverride(t *testing.T) {
	t.Setenv("OP_ACCOUNT", "FromEnv")
	account, err := desktopAccount(context.Background(), " Fixture ")
	if err != nil {
		t.Fatalf("desktopAccount returned error: %v", err)
	}
	if account != "Fixture" {
		t.Fatalf("account = %q, want explicit override", account)
	}
}

func TestDesktopAccountUsesOPAccountEnvironment(t *testing.T) {
	t.Setenv("OP_ACCOUNT", " Fixture ")
	account, err := desktopAccount(context.Background(), "")
	if err != nil {
		t.Fatalf("desktopAccount returned error: %v", err)
	}
	if account != "Fixture" {
		t.Fatalf("account = %q, want OP_ACCOUNT", account)
	}
}

func TestDesktopAccountUsesSDKDefaultWhenUnset(t *testing.T) {
	account, err := desktopAccountWith(context.Background(), "", "")
	if err != nil {
		t.Fatalf("desktopAccount returned error: %v", err)
	}
	if account != DefaultDesktopAccount {
		t.Fatalf("account = %q, want default account", account)
	}
}

func TestNormalizeDesktopOptionsTrimsAndDefaults(t *testing.T) {
	t.Parallel()

	opts := normalizeDesktopOptions(ClientOptions{
		Account:            " Fixture ",
		IntegrationName:    " \t ",
		IntegrationVersion: " ",
	})
	if opts.Account != "Fixture" {
		t.Fatalf("account = %q, want Fixture", opts.Account)
	}
	if opts.IntegrationName != "Agent Secret Broker" {
		t.Fatalf("integration name = %q, want default", opts.IntegrationName)
	}
	if opts.IntegrationVersion != "dev" {
		t.Fatalf("integration version = %q, want dev", opts.IntegrationVersion)
	}

	opts = normalizeDesktopOptions(ClientOptions{
		Account:            "Fixture",
		IntegrationName:    "agent-secretd",
		IntegrationVersion: "1.2.3",
	})
	if opts.IntegrationName != "agent-secretd" || opts.IntegrationVersion != "1.2.3" {
		t.Fatalf("explicit integration info was not preserved: %+v", opts)
	}
}
