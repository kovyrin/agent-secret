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
	if err := os.MkdirAll(child, 0o755); err != nil {
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

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
