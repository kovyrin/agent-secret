package secretref

import (
	"errors"
	"strings"
	"testing"
)

func TestParseOnePasswordReference(t *testing.T) {
	t.Parallel()

	ref, err := Parse("op://Example/Item/token")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ref.Provider != ProviderOnePassword {
		t.Fatalf("Provider = %q, want %q", ref.Provider, ProviderOnePassword)
	}
	if ref.Vault != "Example" || ref.Item != "Item" || ref.Field != "token" {
		t.Fatalf("unexpected parsed 1Password ref: %#v", ref)
	}
}

func TestParseBareBitwardenSecretsManagerReference(t *testing.T) {
	t.Parallel()

	ref, err := Parse("bws://BE8E0AD8-D545-4017-A55A-B02F014D4158")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ref.Provider != ProviderBitwardenSecretsManager {
		t.Fatalf("Provider = %q, want %q", ref.Provider, ProviderBitwardenSecretsManager)
	}
	if ref.Raw != "bws://be8e0ad8-d545-4017-a55a-b02f014d4158" {
		t.Fatalf("Raw = %q", ref.Raw)
	}
	if ref.Source != "" {
		t.Fatalf("Source = %q, want empty", ref.Source)
	}
	if ref.SecretID != "be8e0ad8-d545-4017-a55a-b02f014d4158" {
		t.Fatalf("SecretID = %q", ref.SecretID)
	}
}

func TestParseSourceQualifiedBitwardenSecretsManagerReference(t *testing.T) {
	t.Parallel()

	ref, err := Parse("bws://work-secrets/be8e0ad8-d545-4017-a55a-b02f014d4158")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if ref.Source != "work-secrets" {
		t.Fatalf("Source = %q", ref.Source)
	}
	if ref.SecretID != "be8e0ad8-d545-4017-a55a-b02f014d4158" {
		t.Fatalf("SecretID = %q", ref.SecretID)
	}
}

func TestReferenceHelpers(t *testing.T) {
	t.Parallel()

	if !IsSupported("op://Example/Item/token") {
		t.Fatal("op:// ref was not recognized as supported")
	}
	if !IsSupported("bws://be8e0ad8-d545-4017-a55a-b02f014d4158") {
		t.Fatal("bws:// ref was not recognized as supported")
	}
	if IsSupported("env://TOKEN") {
		t.Fatal("unsupported scheme was recognized as supported")
	}
	if !IsBitwardenSecretsManager("bws://be8e0ad8-d545-4017-a55a-b02f014d4158") {
		t.Fatal("bws:// ref was not recognized as Bitwarden Secrets Manager")
	}
	if IsBitwardenSecretsManager("op://Example/Item/token") {
		t.Fatal("op:// ref was recognized as Bitwarden Secrets Manager")
	}
}

func TestNormalizeSourceAlias(t *testing.T) {
	t.Parallel()

	alias, err := NormalizeSourceAlias(" work.secrets-1 ")
	if err != nil {
		t.Fatalf("NormalizeSourceAlias returned error: %v", err)
	}
	if alias != "work.secrets-1" {
		t.Fatalf("alias = %q", alias)
	}

	for _, raw := range []string{"", "bad alias", "-bad", strings.Repeat("a", 129)} {
		if _, err := NormalizeSourceAlias(raw); !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("NormalizeSourceAlias(%q) error = %v, want ErrInvalidReference", raw, err)
		}
	}
}

func TestParseBitwardenSecretsManagerRejectsPathResources(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"bws://",
		" bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		"bws://work//be8e0ad8-d545-4017-a55a-b02f014d4158",
		"bws://secrets/work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		"bws://work/not-a-uuid",
		"bws://bad source/be8e0ad8-d545-4017-a55a-b02f014d4158",
	} {
		if _, err := Parse(raw); !errors.Is(err, ErrInvalidReference) {
			t.Fatalf("Parse(%q) error = %v, want ErrInvalidReference", raw, err)
		}
	}
}
