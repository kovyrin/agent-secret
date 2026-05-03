package profileconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFindsProfileInParentAndSortsSecrets(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "infra", "terraform")
	if err := os.MkdirAll(child, 0o750); err != nil {
		t.Fatalf("create child dir: %v", err)
	}
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      Z_TOKEN: op://Example/Z/token
      A_TOKEN: op://Example/A/token
`)

	profile, err := Load(LoadOptions{Name: "terraform-cloudflare", StartDir: child})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.SourcePath != filepath.Join(root, "agent-secret.yml") {
		t.Fatalf("SourcePath = %q", profile.SourcePath)
	}
	if profile.Reason != "Terraform DNS management" {
		t.Fatalf("Reason = %q", profile.Reason)
	}
	if profile.TTL != 10*time.Minute {
		t.Fatalf("TTL = %s", profile.TTL)
	}
	if got := profile.Secrets[0].Alias; got != "A_TOKEN" {
		t.Fatalf("first alias = %q, want sorted A_TOKEN", got)
	}
	if got := profile.Secrets[1].Alias; got != "Z_TOKEN" {
		t.Fatalf("second alias = %q, want sorted Z_TOKEN", got)
	}
}

func TestLoadAppliesAccountPrecedence(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
account: Default Account
profiles:
  inherited:
    reason: Inherited
    secrets:
      TOKEN: op://Example/Item/token
  overridden:
    account: Profile Account
    reason: Overridden
    secrets:
      A_TOKEN: op://Example/A/token
      B_TOKEN:
        ref: op://Example/B/token
        account: Secret Account
`)

	inherited, err := Load(LoadOptions{Name: "inherited", StartDir: root})
	if err != nil {
		t.Fatalf("Load inherited returned error: %v", err)
	}
	if inherited.Account != "Default Account" || inherited.Secrets[0].Account != "Default Account" {
		t.Fatalf("inherited account mismatch: profile=%q secrets=%+v", inherited.Account, inherited.Secrets)
	}

	overridden, err := Load(LoadOptions{Name: "overridden", StartDir: root})
	if err != nil {
		t.Fatalf("Load overridden returned error: %v", err)
	}
	if overridden.Account != "Profile Account" {
		t.Fatalf("profile account = %q", overridden.Account)
	}
	if overridden.Secrets[0].Account != "Profile Account" {
		t.Fatalf("profile account was not applied to scalar secret: %+v", overridden.Secrets)
	}
	if overridden.Secrets[1].Account != "Secret Account" {
		t.Fatalf("secret account override was not applied: %+v", overridden.Secrets)
	}
}

func TestLoadIncludesProfiles(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
account: Default Account
profiles:
  base:
    account: Base Account
    reason: Base reason
    ttl: 5m
    secrets:
      BASE_TOKEN: op://Example/Base/token
      OVERRIDE_TOKEN: op://Example/Base/override
  frigate:
    reason: Frigate reason
    ttl: 7m
    secrets:
      FRIGATE_TOKEN: op://Example/Frigate/token
      OVERRIDE_TOKEN: op://Example/Frigate/override
  deploy:
    include:
      - base
      - frigate
    account: Deploy Account
    reason: Deploy reason
    ttl: 10m
    secrets:
      LOCAL_TOKEN: op://Example/Deploy/token
      OVERRIDE_TOKEN: op://Example/Deploy/override
`)

	profile, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.Account != "Deploy Account" {
		t.Fatalf("Account = %q", profile.Account)
	}
	if profile.Reason != "Deploy reason" {
		t.Fatalf("Reason = %q", profile.Reason)
	}
	if profile.TTL != 10*time.Minute {
		t.Fatalf("TTL = %s", profile.TTL)
	}
	want := map[string]struct {
		account string
		ref     string
	}{
		"BASE_TOKEN":     {account: "Base Account", ref: "op://Example/Base/token"},
		"FRIGATE_TOKEN":  {account: "Default Account", ref: "op://Example/Frigate/token"},
		"LOCAL_TOKEN":    {account: "Deploy Account", ref: "op://Example/Deploy/token"},
		"OVERRIDE_TOKEN": {account: "Deploy Account", ref: "op://Example/Deploy/override"},
	}
	if len(profile.Secrets) != len(want) {
		t.Fatalf("secret count = %d, want %d: %+v", len(profile.Secrets), len(want), profile.Secrets)
	}
	for _, secret := range profile.Secrets {
		expected, ok := want[secret.Alias]
		if !ok {
			t.Fatalf("unexpected secret: %+v", secret)
		}
		if secret.Account != expected.account || secret.Ref != expected.ref {
			t.Fatalf("%s = account %q ref %q, want account %q ref %q", secret.Alias, secret.Account, secret.Ref, expected.account, expected.ref)
		}
	}
}

func TestLoadAllowsIncludeOnlyProfile(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  base:
    reason: Base reason
    ttl: 5m
    secrets:
      BASE_TOKEN: op://Example/Base/token
  deploy:
    include:
      - base
`)

	profile, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.Reason != "Base reason" || profile.TTL != 5*time.Minute {
		t.Fatalf("included defaults not applied: reason=%q ttl=%s", profile.Reason, profile.TTL)
	}
	if len(profile.Secrets) != 1 || profile.Secrets[0].Alias != "BASE_TOKEN" {
		t.Fatalf("included secrets not applied: %+v", profile.Secrets)
	}
}

func TestLoadReportsIncludeErrors(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  deploy:
    include:
      - missing
    secrets:
      TOKEN: op://Example/Deploy/token
`)
	_, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound for missing include, got %v", err)
	}

	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  one:
    include:
      - two
    secrets:
      ONE_TOKEN: op://Example/One/token
  two:
    include:
      - one
    secrets:
      TWO_TOKEN: op://Example/Two/token
`)
	_, err = Load(LoadOptions{Name: "one", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for include cycle, got %v", err)
	}
}

func TestLoadUsesDefaultProfileWhenNameIsEmpty(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
default_profile: terraform-cloudflare
profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      TOKEN: op://Example/Cloudflare/token
`)

	profile, err := Load(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.Name != "terraform-cloudflare" {
		t.Fatalf("Name = %q", profile.Name)
	}
	if profile.Reason != "Terraform DNS management" {
		t.Fatalf("Reason = %q", profile.Reason)
	}
}

func TestLoadUsesExplicitConfigPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.yml")
	writeConfig(t, path, `
version: 1
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)

	profile, err := Load(LoadOptions{Name: "one", ConfigPath: path, StartDir: "/"})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.SourcePath != path {
		t.Fatalf("SourcePath = %q, want %q", profile.SourcePath, path)
	}
}

func TestLoadMetadataReadsTopLevelAccountWithoutDefaultProfile(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
account: Default Account
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)

	metadata, err := LoadMetadata(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("LoadMetadata returned error: %v", err)
	}
	if metadata.Account != "Default Account" {
		t.Fatalf("Account = %q", metadata.Account)
	}
	if metadata.SourcePath != filepath.Join(root, "agent-secret.yml") {
		t.Fatalf("SourcePath = %q", metadata.SourcePath)
	}
}

func TestLoadReportsMissingDefaultProfile(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)

	_, err := Load(LoadOptions{StartDir: root})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound, got %v", err)
	}
}

func TestLoadReportsProfileConfigErrors(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  broken:
    reason: Broken
    ttl: tomorrow
    secrets:
      TOKEN: op://Example/Item/token
`)

	_, err := Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestLoadReportsUnknownFieldsAndInvalidVersion(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  broken:
    reason: Broken
    unknown: nope
    secrets:
      TOKEN: op://Example/Item/token
`)
	_, err := Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for unknown field, got %v", err)
	}

	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 2
profiles:
  broken:
    reason: Broken
    secrets:
      TOKEN: op://Example/Item/token
`)
	_, err = Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for version, got %v", err)
	}
}

func TestLoadReportsInvalidSecrets(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  broken:
    reason: Broken
    secrets:
      TOKEN: ""
`)
	_, err := Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for empty ref, got %v", err)
	}

	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  broken:
    reason: Broken
`)
	_, err = Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing secrets, got %v", err)
	}

	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  broken:
    reason: Broken
    secrets:
      TOKEN:
        ref: op://Example/Item/token
        unknown: nope
`)
	_, err = Load(LoadOptions{Name: "broken", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for unknown secret field, got %v", err)
	}
}

func TestFindUsesDotfileAndRejectsExplicitDirectory(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, ".agent-secret.yml"), `
version: 1
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)

	path, err := Find("", root)
	if err != nil {
		t.Fatalf("Find returned error: %v", err)
	}
	if path != filepath.Join(root, ".agent-secret.yml") {
		t.Fatalf("path = %q", path)
	}

	_, err = Find(root, root)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for directory, got %v", err)
	}
}

func TestLoadReportsMissingConfigAndProfile(t *testing.T) {
	_, err := Load(LoadOptions{Name: "missing", StartDir: t.TempDir()})
	if !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("expected ErrConfigNotFound, got %v", err)
	}

	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)
	_, err = Load(LoadOptions{Name: "two", StartDir: root})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound, got %v", err)
	}
}

func writeConfig(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
