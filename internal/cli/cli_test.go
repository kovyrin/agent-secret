package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
)

func TestParseExecBuildsValidatedRequest(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "terraform")
	t.Setenv("PATH", dir)
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	parser := NewParser(func() time.Time { return now })

	command, err := parser.Parse([]string{
		"exec",
		"--reason", "  Terraform plan  ",
		"--cwd", dir,
		"--ttl", "90s",
		"--secret", "TOKEN=op://Example Vault/Cloudflare/token",
		"--force-refresh",
		"--",
		"terraform", "plan",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if command.Kind != KindExec {
		t.Fatalf("kind = %s, want exec", command.Kind)
	}
	req := command.ExecRequest
	if req.Reason != "Terraform plan" || req.TTL != 90*time.Second || !req.ForceRefresh {
		t.Fatalf("unexpected request policy: %+v", req)
	}
	if req.Command[0] != "terraform" || req.ResolvedExecutable == "" {
		t.Fatalf("unexpected command resolution: %+v", req.Command)
	}
	if req.DeliveryMode != request.DeliveryEnvExec {
		t.Fatalf("delivery mode = %s", req.DeliveryMode)
	}
}

func TestParseExecBuildsRequestFromProfile(t *testing.T) {
	root := t.TempDir()
	infraDir := filepath.Join(root, "infra")
	if err := os.MkdirAll(infraDir, 0o755); err != nil {
		t.Fatalf("create infra dir: %v", err)
	}
	writeExecutable(t, infraDir, "terraform")
	writeProfileConfig(t, root, `
version: 1
account: Default Account
profiles:
  terraform-cloudflare:
    account: Terraform Account
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
      EXTRA_TOKEN:
        ref: op://Example/Extra/token
        account: Extra Account
`)
	t.Chdir(root)
	t.Setenv("PATH", infraDir)
	now := time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC)
	parser := NewParser(func() time.Time { return now })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "terraform-cloudflare",
		"--",
		"terraform", "plan",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if req.Reason != "Terraform DNS management" {
		t.Fatalf("Reason = %q", req.Reason)
	}
	if req.TTL != 10*time.Minute {
		t.Fatalf("TTL = %s", req.TTL)
	}
	if len(req.Secrets) != 2 {
		t.Fatalf("secret count = %d", len(req.Secrets))
	}
	if req.Secrets[0].Alias != "CLOUDFLARE_API_TOKEN" || req.Secrets[1].Alias != "EXTRA_TOKEN" {
		t.Fatalf("secrets not sorted from profile: %+v", req.Secrets)
	}
	if req.Secrets[0].Account != "Terraform Account" || req.Secrets[1].Account != "Extra Account" {
		t.Fatalf("accounts not applied from profile config: %+v", req.Secrets)
	}
}

func TestParseExecFiltersProfileSecretsWithOnly(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "ansible-playbook")
	writeProfileConfig(t, root, `
version: 1
profiles:
  ansible:
    account: Ansible Account
    reason: Profile reason
    ttl: 10m
    secrets:
      A_TOKEN: op://Example/A/token
      B_TOKEN: op://Example/B/token
      C_TOKEN: op://Example/C/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "ansible",
		"--only", "B_TOKEN,A_TOKEN",
		"--secret", "EXTRA_TOKEN=op://Example/Extra/token",
		"--",
		"ansible-playbook", "site.yml",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 3 {
		t.Fatalf("secret count = %d, want 3: %+v", len(req.Secrets), req.Secrets)
	}
	for index, want := range []string{"A_TOKEN", "B_TOKEN", "EXTRA_TOKEN"} {
		if req.Secrets[index].Alias != want {
			t.Fatalf("secret %d alias = %q, want %q: %+v", index, req.Secrets[index].Alias, want, req.Secrets)
		}
		if req.Secrets[index].Account != "Ansible Account" {
			t.Fatalf("secret %d account = %q, want profile account", index, req.Secrets[index].Account)
		}
	}
}

func TestParseExecBuildsRequestFromEnvFiles(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	firstEnv := filepath.Join(root, "first.env")
	secondEnv := filepath.Join(root, "second.env")
	writeConfigFile(t, firstEnv, `
TOKEN=op://Example/Item/token
PLAIN=first
OVERRIDE=first
REMOVED=op://Example/Old/token
`)
	writeConfigFile(t, secondEnv, `
OVERRIDE=second
REMOVED=plain-now
NEXT=op://Example/Next/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	t.Setenv("TOKEN", "parent-token")
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--reason", "Env file command",
		"--env-file", firstEnv,
		"--env-file", secondEnv,
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 2 {
		t.Fatalf("secret count = %d, want 2: %+v", len(req.Secrets), req.Secrets)
	}
	for index, want := range []string{"NEXT", "TOKEN"} {
		if req.Secrets[index].Alias != want {
			t.Fatalf("secret %d alias = %q, want %q: %+v", index, req.Secrets[index].Alias, want, req.Secrets)
		}
	}
	if got := lookupTestEnv(req.Env, "TOKEN"); got != "" {
		t.Fatalf("env-file secret alias survived in child base env: TOKEN=%q", got)
	}
	if got := lookupTestEnv(req.Env, "PLAIN"); got != "first" {
		t.Fatalf("PLAIN = %q, want first", got)
	}
	if got := lookupTestEnv(req.Env, "OVERRIDE"); got != "second" {
		t.Fatalf("OVERRIDE = %q, want second", got)
	}
	if got := lookupTestEnv(req.Env, "REMOVED"); got != "plain-now" {
		t.Fatalf("REMOVED = %q, want plain-now", got)
	}
}

func TestParseExecEnvFileDoesNotLoadDefaultProfile(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  deploy:
    reason: Default deploy
    secrets:
      DEFAULT_TOKEN: op://Example/Default/token
`)
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, "PLAIN=kept\n")
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	_, err := parser.Parse([]string{
		"exec",
		"--reason", "Plain env file",
		"--env-file", envPath,
		"--",
		"tool",
	})
	if !errors.Is(err, request.ErrInvalidReference) {
		t.Fatalf("expected plain-only env file not to load default profile, got %v", err)
	}
}

func TestParseExecFiltersEnvFileSecretsWithOnly(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, `
BETA_TOKEN=op://Example/Beta/token
PRODUCTION_TOKEN=op://Example/Production/token
PLAIN=kept
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	t.Setenv("PRODUCTION_TOKEN", "parent-production")
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--reason", "Env file command",
		"--env-file", envPath,
		"--only", "BETA_TOKEN",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 1 || req.Secrets[0].Alias != "BETA_TOKEN" {
		t.Fatalf("secrets = %+v, want only BETA_TOKEN", req.Secrets)
	}
	if got := lookupTestEnv(req.Env, "PRODUCTION_TOKEN"); got != "" {
		t.Fatalf("filtered env-file secret alias survived in child base env: PRODUCTION_TOKEN=%q", got)
	}
	if got := lookupTestEnv(req.Env, "PLAIN"); got != "kept" {
		t.Fatalf("PLAIN = %q, want kept", got)
	}
}

func TestParseExecCombinesProfileEnvFileSecretAndOnlyPredictably(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
profiles:
  deploy:
    account: Profile Account
    reason: Deploy
    secrets:
      PROFILE_KEEP: op://Example/Profile/keep
      PROFILE_DROP: op://Example/Profile/drop
`)
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, `
FILE_KEEP=op://Example/File/keep
FILE_DROP=op://Example/File/drop
PLAIN=kept
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "deploy",
		"--env-file", envPath,
		"--only", "PROFILE_KEEP,FILE_KEEP",
		"--secret", "EXPLICIT_TOKEN=op://Example/Explicit/token",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 3 {
		t.Fatalf("secret count = %d, want 3: %+v", len(req.Secrets), req.Secrets)
	}
	for index, want := range []string{"PROFILE_KEEP", "EXPLICIT_TOKEN", "FILE_KEEP"} {
		if req.Secrets[index].Alias != want {
			t.Fatalf("secret %d alias = %q, want %q: %+v", index, req.Secrets[index].Alias, want, req.Secrets)
		}
		if req.Secrets[index].Account != "Profile Account" {
			t.Fatalf("secret %d account = %q, want Profile Account: %+v", index, req.Secrets[index].Account, req.Secrets)
		}
	}
	if got := lookupTestEnv(req.Env, "PLAIN"); got != "kept" {
		t.Fatalf("PLAIN = %q, want kept", got)
	}
}

func TestParseExecAccountAppliesToExplicitAndEnvFileSecrets(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, "FILE_TOKEN=op://Example/File/token\n")
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--reason", "Account command",
		"--account", "fixture.1password.com",
		"--secret", "EXPLICIT_TOKEN=op://Example/Explicit/token",
		"--env-file", envPath,
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 2 {
		t.Fatalf("secret count = %d, want 2: %+v", len(req.Secrets), req.Secrets)
	}
	for _, secret := range req.Secrets {
		if secret.Account != "fixture.1password.com" {
			t.Fatalf("%s account = %q, want fixture.1password.com: %+v", secret.Alias, secret.Account, req.Secrets)
		}
	}
}

func TestParseExecAccountPrecedenceInCombinedSources(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
profiles:
  deploy:
    reason: Deploy
    secrets:
      PROFILE_TOKEN: op://Example/Profile/token
      PROFILE_OVERRIDE:
        ref: op://Example/Profile/override
        account: Secret Account
`)
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, "FILE_TOKEN=op://Example/File/token\n")
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "deploy",
		"--account", "CLI Account",
		"--env-file", envPath,
		"--secret", "EXPLICIT_TOKEN=op://Example/Explicit/token",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	got := make(map[string]string)
	for _, secret := range command.ExecRequest.Secrets {
		got[secret.Alias] = secret.Account
	}
	want := map[string]string{
		"EXPLICIT_TOKEN":   "CLI Account",
		"FILE_TOKEN":       "CLI Account",
		"PROFILE_OVERRIDE": "Secret Account",
		"PROFILE_TOKEN":    "CLI Account",
	}
	for alias, account := range want {
		if got[alias] != account {
			t.Fatalf("%s account = %q, want %q: %+v", alias, got[alias], account, command.ExecRequest.Secrets)
		}
	}
}

func TestParseExecAccountAppliesToProfileSecretsWithoutConfigAccount(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
profiles:
  deploy:
    reason: Deploy with account flag
    secrets:
      PROFILE_TOKEN: op://Example/Profile/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "deploy",
		"--account", "fixture.1password.com",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 1 || req.Secrets[0].Account != "fixture.1password.com" {
		t.Fatalf("secrets = %+v, want profile secret with CLI account", req.Secrets)
	}
}

func TestParseExecEnvFileSecretsInheritProfileAccount(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
profiles:
  deploy:
    account: Deploy Account
    reason: Deploy with env file
    secrets:
      PROFILE_TOKEN: op://Example/Profile/token
`)
	envPath := filepath.Join(root, ".env")
	writeConfigFile(t, envPath, "FILE_TOKEN=op://Example/File/token\n")
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "deploy",
		"--account", "CLI Account",
		"--env-file", envPath,
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 2 {
		t.Fatalf("secret count = %d, want 2: %+v", len(req.Secrets), req.Secrets)
	}
	for _, secret := range req.Secrets {
		if secret.Account != "Deploy Account" {
			t.Fatalf("%s account = %q, want Deploy Account: %+v", secret.Alias, secret.Account, req.Secrets)
		}
	}
}

func TestParseExecRejectsInvalidOnlyAlias(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
profiles:
  one:
    reason: One
    secrets:
      TOKEN: op://Example/Item/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	_, err := parser.Parse([]string{
		"exec",
		"--profile", "one",
		"--only", "MISSING_TOKEN",
		"--",
		"tool",
	})
	if !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("expected ErrInvalidArguments for missing --only alias, got %v", err)
	}

	_, err = parser.Parse([]string{
		"exec",
		"--reason", "Explicit only",
		"--secret", "TOKEN=op://Example/Item/token",
		"--only", "TOKEN",
		"--",
		"tool",
	})
	if !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("expected ErrInvalidArguments for --only without loaded profile, got %v", err)
	}
}

func TestParseExecBuildsRequestFromDefaultProfile(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "terraform")
	writeProfileConfig(t, root, `
version: 1
account: Default Account
default_profile: terraform-cloudflare
profiles:
  terraform-cloudflare:
    reason: Default Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--",
		"terraform", "plan",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if req.Reason != "Default Terraform DNS management" {
		t.Fatalf("Reason = %q", req.Reason)
	}
	if req.TTL != 10*time.Minute {
		t.Fatalf("TTL = %s", req.TTL)
	}
	if len(req.Secrets) != 1 || req.Secrets[0].Alias != "CLOUDFLARE_API_TOKEN" {
		t.Fatalf("secrets = %+v", req.Secrets)
	}
	if req.Secrets[0].Account != "Default Account" {
		t.Fatalf("default profile account = %q", req.Secrets[0].Account)
	}
}

func TestParseExecBuildsDefaultProfileFromExplicitConfigPath(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "custom-agent-secret.yml")
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "terraform")
	writeConfigFile(t, configPath, `
version: 1
default_profile: terraform-cloudflare
profiles:
  terraform-cloudflare:
    reason: Explicit config default
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--config", configPath,
		"--",
		"terraform", "plan",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if req.Reason != "Explicit config default" {
		t.Fatalf("Reason = %q", req.Reason)
	}
	if len(req.Secrets) != 1 || req.Secrets[0].Alias != "CLOUDFLARE_API_TOKEN" {
		t.Fatalf("secrets = %+v", req.Secrets)
	}
}

func TestParseExecExplicitSecretsDoNotLoadDefaultProfile(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
account: Default Account
default_profile: extra
profiles:
  extra:
    reason: Extra
    secrets:
      EXTRA_TOKEN: op://Example/Extra/token
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--reason", "Explicit only",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 1 || req.Secrets[0].Alias != "TOKEN" {
		t.Fatalf("default profile leaked into explicit secret request: %+v", req.Secrets)
	}
	if req.Secrets[0].Account != "" {
		t.Fatalf("default account leaked into explicit secret request: %+v", req.Secrets)
	}
}

func TestParseExecMergesProfileAndExplicitSecretsWithOverrides(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "ansible-playbook")
	writeProfileConfig(t, root, `
version: 1
profiles:
  ansible:
    account: Ansible Account
    reason: Profile reason
    ttl: 10m
    secrets:
      BECOME_PASSWORD: op://Example/Ansible/password
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	command, err := parser.Parse([]string{
		"exec",
		"--profile", "ansible",
		"--reason", "CLI reason",
		"--ttl", "90s",
		"--secret", "CADDY_TOKEN=op://Example/Caddy/token",
		"--",
		"ansible-playbook", "site.yml",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if req.Reason != "CLI reason" {
		t.Fatalf("Reason = %q", req.Reason)
	}
	if req.TTL != 90*time.Second {
		t.Fatalf("TTL = %s", req.TTL)
	}
	if len(req.Secrets) != 2 {
		t.Fatalf("secret count = %d", len(req.Secrets))
	}
	if req.Secrets[0].Account != "Ansible Account" || req.Secrets[1].Account != "Ansible Account" {
		t.Fatalf("profile account was not applied to profile and explicit secrets: %+v", req.Secrets)
	}
}

func TestParseExecRejectsUnsafeOrUnsupportedForms(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "tool")
	parser := NewParser(func() time.Time { return time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC) })

	tests := []struct {
		name string
		args []string
		want error
	}{
		{
			name: "missing command boundary",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "tool"},
			want: ErrShellStringCommand,
		},
		{
			name: "json",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--json", "--", "tool"},
			want: ErrUnsupportedExecJSON,
		},
		{
			name: "reuse",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--reuse", "--", "tool"},
			want: ErrUnsupportedReuse,
		},
		{
			name: "missing reason",
			args: []string{"exec", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--", "tool"},
			want: request.ErrInvalidReason,
		},
		{
			name: "blank reason",
			args: []string{"exec", "--reason", " \t", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--", "tool"},
			want: request.ErrInvalidReason,
		},
		{
			name: "overlong reason",
			args: []string{"exec", "--reason", strings.Repeat("x", request.MaxReasonLength+1), "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--", "tool"},
			want: request.ErrInvalidReason,
		},
		{
			name: "bad secret mapping",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--secret", "TOKEN", "--", "tool"},
			want: ErrInvalidArguments,
		},
		{
			name: "blank env file",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--env-file", " ", "--", "tool"},
			want: ErrInvalidArguments,
		},
		{
			name: "only without bulk source",
			args: []string{"exec", "--reason", "reason", "--cwd", dir, "--secret", "TOKEN=op://Example/Item/token", "--only", "TOKEN", "--", "tool"},
			want: ErrInvalidArguments,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parser.Parse(tt.args)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestParseDaemonAndDoctorCommands(t *testing.T) {
	t.Parallel()

	parser := NewParser(time.Now)
	for _, tt := range []struct {
		args []string
		want Kind
	}{
		{args: []string{"daemon", "status"}, want: KindDaemonStatus},
		{args: []string{"daemon", "start"}, want: KindDaemonStart},
		{args: []string{"daemon", "stop"}, want: KindDaemonStop},
		{args: []string{"doctor"}, want: KindDoctor},
		{args: []string{"install-cli"}, want: KindInstallCLI},
	} {
		command, err := parser.Parse(tt.args)
		if err != nil {
			t.Fatalf("Parse(%v) returned error: %v", tt.args, err)
		}
		if command.Kind != tt.want {
			t.Fatalf("Parse(%v) kind = %s, want %s", tt.args, command.Kind, tt.want)
		}
	}
}

func TestParseInstallCLIOptions(t *testing.T) {
	t.Parallel()

	parser := NewParser(time.Now)
	command, err := parser.Parse([]string{"install-cli", "--bin-dir", "/tmp/bin", "--force"})
	if err != nil {
		t.Fatalf("Parse install-cli returned error: %v", err)
	}
	if command.Kind != KindInstallCLI {
		t.Fatalf("kind = %s, want %s", command.Kind, KindInstallCLI)
	}
	if command.InstallCLIOptions.BinDir != "/tmp/bin" {
		t.Fatalf("bin dir = %q, want /tmp/bin", command.InstallCLIOptions.BinDir)
	}
	if !command.InstallCLIOptions.Force {
		t.Fatal("force = false, want true")
	}
}

func TestHelpIsDetailedAndValueFree(t *testing.T) {
	t.Parallel()

	parser := NewParser(time.Now)
	tests := []struct {
		name  string
		args  []string
		wants []string
	}{
		{
			name:  "top",
			args:  []string{"--help"},
			wants: []string{"agent-secret controls", "exec", "install-cli", "daemon", "doctor", "my.1password.com"},
		},
		{
			name:  "exec",
			args:  []string{"exec", "--help"},
			wants: []string{"--reason", "--secret", "--profile", "--only", "--env-file", "--account", "include:", "account:", "default_profile", "agent-secret.yml", "--force-refresh", "Default account", "audit.jsonl", "stdin", "stdout", "stderr"},
		},
		{
			name:  "daemon",
			args:  []string{"daemon", "--help"},
			wants: []string{"daemon status", "daemon start", "daemon stop", "in-memory"},
		},
		{
			name:  "doctor",
			args:  []string{"doctor", "--help"},
			wants: []string{"non-secret local diagnostics", "1Password"},
		},
		{
			name:  "install-cli",
			args:  []string{"install-cli", "--help"},
			wants: []string{"install", "command-line", "--bin-dir", "--force", "Agent Secret.app"},
		},
	}

	for _, tt := range tests {
		command, err := parser.Parse(tt.args)
		if !errors.Is(err, ErrHelpRequested) {
			t.Fatalf("%s: expected help error, got %v", tt.name, err)
		}
		for _, want := range tt.wants {
			if !strings.Contains(command.HelpText, want) {
				t.Fatalf("%s help missing %q:\n%s", tt.name, want, command.HelpText)
			}
		}
		if strings.Contains(command.HelpText, "synthetic-secret-value") {
			t.Fatalf("%s help contains secret-looking canary value", tt.name)
		}
	}
}

func writeExecutable(t *testing.T, dir string, name string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
}

func writeProfileConfig(t *testing.T, dir string, contents string) {
	t.Helper()

	writeConfigFile(t, filepath.Join(dir, "agent-secret.yml"), contents)
}

func writeConfigFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
}

func lookupTestEnv(env []string, key string) string {
	for _, entry := range env {
		gotKey, value, ok := strings.Cut(entry, "=")
		if ok && gotKey == key {
			return value
		}
	}
	return ""
}
