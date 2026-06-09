package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestParseExecBuildsValidatedRequest(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "terraform")
	t.Setenv("PATH", dir)
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "  Terraform plan  ",
		"--cwd", dir,
		"--ttl", "90s",
		"--account", "Work",
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
	if !req.ReceivedAt.IsZero() || !req.ExpiresAt.IsZero() {
		t.Fatalf("client request times = received %s expires %s, want daemon-owned zero values", req.ReceivedAt, req.ExpiresAt)
	}
}

func TestParseExecRejectsMutableExecutableWithoutOptIn(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "tool")
	t.Setenv("PATH", dir)

	_, err := NewParser().Parse([]string{
		"exec",
		"--reason", "Run tool",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool",
	})
	if err == nil {
		t.Fatal("Parse returned nil error, want mutable executable rejection")
	}
	if !strings.Contains(err.Error(), "--allow-mutable-executable") {
		t.Fatalf("error = %v, want opt-in guidance", err)
	}
}

func TestParseExecMutableExecutableOptInIsRecorded(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "tool")
	t.Setenv("PATH", dir)

	command, err := NewParser().Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run tool",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !command.ExecRequest.AllowMutableExecutable {
		t.Fatalf("AllowMutableExecutable = false, want true")
	}
}

func TestParseExecBuildsRequestFromProfile(t *testing.T) {
	root := t.TempDir()
	infraDir := filepath.Join(root, "infra")
	if err := os.MkdirAll(infraDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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

func TestParseExecBuildsBitwardenRequestFromProfileSource(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	writeProfileConfig(t, root, `
version: 1
sources:
  bitwarden:
    work-secrets:
      kind: secrets_manager
      token_alias: work
profiles:
  deploy:
    reason: Deploy
    secrets:
      API_TOKEN: bws://be8e0ad8-d545-4017-a55a-b02f014d4158
`)
	t.Chdir(root)
	t.Setenv("PATH", root)

	command, err := NewParser().Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--profile", "deploy",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	secret := command.ExecRequest.Secrets[0]
	if secret.Account != "" {
		t.Fatalf("Bitwarden secret account = %q, want empty", secret.Account)
	}
	if secret.Source != "work-secrets" || secret.Bitwarden.TokenAlias != "work" {
		t.Fatalf("Bitwarden source metadata = source %q token %q", secret.Source, secret.Bitwarden.TokenAlias)
	}
}

func TestParseExecInfersSingleLocalBitwardenTokenAlias(t *testing.T) {
	parser := NewParser()
	parser.listBitwardenTokenAliases = func(context.Context) ([]string, error) {
		return []string{"work"}, nil
	}

	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Deploy",
		"--secret", "API_TOKEN=bws://be8e0ad8-d545-4017-a55a-b02f014d4158",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	secret := command.ExecRequest.Secrets[0]
	if secret.Source != "work" || secret.Bitwarden.TokenAlias != "work" || secret.Account != "" {
		t.Fatalf("Bitwarden secret metadata = %+v", secret)
	}
}

func TestResolveImplicitBitwardenSourceFromLocalAliases(t *testing.T) {
	t.Parallel()

	cache := bitwardenLocalAliasCache{
		list: func(context.Context) ([]string, error) {
			return []string{"work"}, nil
		},
	}
	source, err := resolveImplicitBitwardenSource(
		"bws://be8e0ad8-d545-4017-a55a-b02f014d4158",
		profileconfig.Sources{},
		&cache,
	)
	if err != nil {
		t.Fatalf("resolveImplicitBitwardenSource returned error: %v", err)
	}
	if source != "work" {
		t.Fatalf("source = %q, want work", source)
	}
}

func TestResolveImplicitBitwardenSourceRejectsLocalAliasAmbiguity(t *testing.T) {
	t.Parallel()

	cache := bitwardenLocalAliasCache{
		list: func(context.Context) ([]string, error) {
			return []string{"personal", "work"}, nil
		},
	}
	_, err := resolveImplicitBitwardenSource(
		"bws://be8e0ad8-d545-4017-a55a-b02f014d4158",
		profileconfig.Sources{},
		&cache,
	)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("resolveImplicitBitwardenSource error = %v, want ambiguity", err)
	}
}

func TestSingleConfiguredBitwardenSource(t *testing.T) {
	t.Parallel()

	if _, ok := singleConfiguredBitwardenSource(profileconfig.Sources{}); ok {
		t.Fatal("empty sources returned ok=true")
	}
	source, ok := singleConfiguredBitwardenSource(profileconfig.Sources{
		Bitwarden: map[string]request.BitwardenSource{
			"work": {Alias: "work", TokenAlias: "work-token"},
		},
	})
	if !ok || source.Alias != "work" || source.TokenAlias != "work-token" {
		t.Fatalf("single source = %+v ok=%v", source, ok)
	}
	if _, ok := singleConfiguredBitwardenSource(profileconfig.Sources{
		Bitwarden: map[string]request.BitwardenSource{
			"personal": {Alias: "personal"},
			"work":     {Alias: "work"},
		},
	}); ok {
		t.Fatal("multiple sources returned ok=true")
	}
}

func TestParseExecRejectsAmbiguousLocalBitwardenTokenAliases(t *testing.T) {
	parser := NewParser()
	parser.listBitwardenTokenAliases = func(context.Context) ([]string, error) {
		return []string{"personal", "work"}, nil
	}

	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)

	_, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Deploy",
		"--secret", "API_TOKEN=bws://be8e0ad8-d545-4017-a55a-b02f014d4158",
		"--",
		"tool",
	})
	if !errors.Is(err, request.ErrInvalidReference) {
		t.Fatalf("Parse error = %v, want invalid reference", err)
	}
}

func TestParseExecUsesExplicitBitwardenSourceWithoutLocalAliasLookup(t *testing.T) {
	parser := NewParser()
	parser.listBitwardenTokenAliases = func(context.Context) ([]string, error) {
		t.Fatal("explicit Bitwarden source should not list local token aliases")
		return nil, nil
	}

	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Deploy",
		"--secret", "API_TOKEN=bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	secret := command.ExecRequest.Secrets[0]
	if secret.Source != "work" || secret.Bitwarden.TokenAlias != "work" {
		t.Fatalf("Bitwarden secret metadata = %+v", secret)
	}
}

func TestParseExecRejectsMissingLocalBitwardenTokenAlias(t *testing.T) {
	parser := NewParser()
	parser.listBitwardenTokenAliases = func(context.Context) ([]string, error) {
		return nil, nil
	}

	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)

	_, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Deploy",
		"--secret", "API_TOKEN=bws://be8e0ad8-d545-4017-a55a-b02f014d4158",
		"--",
		"tool",
	})
	if !errors.Is(err, request.ErrInvalidReference) {
		t.Fatalf("Parse error = %v, want invalid reference", err)
	}
	if !strings.Contains(err.Error(), "install one token alias") {
		t.Fatalf("Parse error = %v, want install guidance", err)
	}
}

func TestParseExecRejectsConflictingBitwardenSourceMetadata(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	writeProfileConfig(t, root, `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      token_alias: work
profiles:
  deploy:
    reason: Deploy
    secrets:
      API_TOKEN:
        ref: bws://personal/be8e0ad8-d545-4017-a55a-b02f014d4158
        source: work
`)
	t.Chdir(root)
	t.Setenv("PATH", root)

	_, err := NewParser().Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--profile", "deploy",
		"--",
		"tool",
	})
	if !errors.Is(err, profileconfig.ErrInvalidConfig) {
		t.Fatalf("Parse error = %v, want invalid config", err)
	}
	if !strings.Contains(err.Error(), "does not match ref source") {
		t.Fatalf("Parse error = %v, want source mismatch", err)
	}
}

func TestParseExecRejectsUnknownConfiguredBitwardenSource(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	writeProfileConfig(t, root, `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      token_alias: work
profiles:
  deploy:
    reason: Deploy
    secrets:
      API_TOKEN: bws://personal/be8e0ad8-d545-4017-a55a-b02f014d4158
`)
	t.Chdir(root)
	t.Setenv("PATH", root)

	_, err := NewParser().Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--profile", "deploy",
		"--",
		"tool",
	})
	if !errors.Is(err, profileconfig.ErrInvalidConfig) {
		t.Fatalf("Parse error = %v, want invalid config", err)
	}
	if !strings.Contains(err.Error(), "references unknown Bitwarden source") {
		t.Fatalf("Parse error = %v, want unknown source", err)
	}
}

func TestParseBitwardenTokenCommands(t *testing.T) {
	t.Parallel()

	command, err := NewParser().Parse([]string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
		"--from-stdin",
		"--json",
	})
	if err != nil {
		t.Fatalf("Parse install returned error: %v", err)
	}
	if command.Kind != KindBitwarden ||
		command.BitwardenOptions.Operation != BitwardenTokenInstall ||
		command.BitwardenOptions.Alias != "work" ||
		!command.BitwardenOptions.FromStdin ||
		!command.OutputJSON {
		t.Fatalf("install command = %+v", command)
	}

	interactive, err := NewParser().Parse([]string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
	})
	if err != nil {
		t.Fatalf("Parse interactive install returned error: %v", err)
	}
	if interactive.BitwardenOptions.Operation != BitwardenTokenInstall ||
		interactive.BitwardenOptions.Alias != "work" ||
		interactive.BitwardenOptions.FromStdin {
		t.Fatalf("interactive install command = %+v", interactive)
	}

	status, err := NewParser().Parse([]string{
		"bitwarden",
		"secrets-manager",
		"token",
		"status",
		"--alias", "work",
	})
	if err != nil {
		t.Fatalf("Parse status returned error: %v", err)
	}
	if status.BitwardenOptions.Operation != BitwardenTokenStatus {
		t.Fatalf("status operation = %q", status.BitwardenOptions.Operation)
	}

	remove, err := NewParser().Parse([]string{
		"bitwarden",
		"secrets-manager",
		"token",
		"remove",
		"--alias", "work",
	})
	if err != nil {
		t.Fatalf("Parse remove returned error: %v", err)
	}
	if remove.BitwardenOptions.Operation != BitwardenTokenRemove {
		t.Fatalf("remove operation = %q", remove.BitwardenOptions.Operation)
	}
}

func TestParseBitwardenRejectsInvalidTokenCommands(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"bitwarden", "sm", "token", "install", "--alias", "work", "--from-stdin"},
		{"bitwarden", "secrets-manager", "token", "status", "--alias", "work", "--from-stdin"},
		{"bitwarden", "secrets-manager", "token", "remove"},
		{"bitwarden", "secrets-manager", "token", "status", "--alias", "work", "extra"},
	} {
		if _, err := NewParser().Parse(args); !errors.Is(err, ErrInvalidArguments) {
			t.Fatalf("Parse(%v) error = %v, want ErrInvalidArguments", args, err)
		}
	}
}

func TestParseBitwardenHelp(t *testing.T) {
	t.Parallel()

	command, err := NewParser().Parse([]string{"bitwarden", "--help"})
	if !errors.Is(err, ErrHelpRequested) {
		t.Fatalf("Parse help error = %v, want ErrHelpRequested", err)
	}
	if command.HelpText == "" || !strings.Contains(command.HelpText, "secrets-manager") {
		t.Fatalf("help text = %q", command.HelpText)
	}
}

func TestParseExecFiltersProfileSecretsWithOnly(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Env file command",
		"--account", "Work",
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
	if got := lookupTestEnv(command.ExecEnv, "TOKEN"); got != "" {
		t.Fatalf("env-file secret alias survived in child base env: TOKEN=%q", got)
	}
	if got := lookupTestEnv(command.ExecEnv, "PLAIN"); got != "first" {
		t.Fatalf("PLAIN = %q, want first", got)
	}
	if got := lookupTestEnv(command.ExecEnv, "OVERRIDE"); got != "second" {
		t.Fatalf("OVERRIDE = %q, want second", got)
	}
	if got := lookupTestEnv(command.ExecEnv, "REMOVED"); got != "plain-now" {
		t.Fatalf("REMOVED = %q, want plain-now", got)
	}
	if req.EnvironmentFingerprint != request.EnvironmentFingerprint(command.ExecEnv) {
		t.Fatalf("environment fingerprint = %q, want fingerprint of effective env", req.EnvironmentFingerprint)
	}
}

func TestParseExecEnvFileDoesNotLoadDefaultProfile(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	_, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Env file command",
		"--account", "Work",
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
	if got := lookupTestEnv(command.ExecEnv, "PRODUCTION_TOKEN"); got != "" {
		t.Fatalf("filtered env-file secret alias survived in child base env: PRODUCTION_TOKEN=%q", got)
	}
	if got := lookupTestEnv(command.ExecEnv, "PLAIN"); got != "kept" {
		t.Fatalf("PLAIN = %q, want kept", got)
	}
}

func TestParseExecCombinesProfileEnvFileSecretAndOnlyPredictably(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if got := lookupTestEnv(command.ExecEnv, "PLAIN"); got != "kept" {
		t.Fatalf("PLAIN = %q, want kept", got)
	}
}

func TestParseExecAccountDefaultPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		opAccount  string
		appAccount string
		want       string
	}{
		{name: "OP_ACCOUNT", opAccount: " Personal ", want: "Personal"},
		{name: "app account", opAccount: " Personal ", appAccount: " Work ", want: "Work"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			binDir := filepath.Join(root, "bin")
			if err := os.MkdirAll(binDir, 0o750); err != nil {
				t.Fatalf("create bin dir: %v", err)
			}
			writeExecutable(t, binDir, "tool")
			t.Chdir(root)
			t.Setenv("PATH", binDir)
			if tt.opAccount != "" {
				t.Setenv("OP_ACCOUNT", tt.opAccount)
			}
			if tt.appAccount != "" {
				t.Setenv("AGENT_SECRET_1PASSWORD_ACCOUNT", tt.appAccount)
			}

			command, err := NewParser().Parse([]string{
				"exec", "--allow-mutable-executable", "--reason", "Account default",
				"--secret", "TOKEN=op://Example/Item/token",
				"--", "tool",
			})
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if got := command.ExecRequest.Secrets[0].Account; got != tt.want {
				t.Fatalf("account = %q, want %q: %+v", got, tt.want, command.ExecRequest.Secrets)
			}
		})
	}
}

func TestParseExecExplicitAccountBeatsProjectConfigForDirectSecrets(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
account: Project Account
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Deploy",
		"--account", "CLI Account",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := command.ExecRequest.Secrets[0].Account; got != "CLI Account" {
		t.Fatalf("direct secret account = %q, want CLI Account: %+v", got, command.ExecRequest.Secrets)
	}
}

func TestParseExecAccountPrecedenceInCombinedSources(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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

func TestParseExecEnvFileSecretsInheritProfileAccount(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	_, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
		"--allow-mutable-executable",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--config", configPath,
		"--account", "Work",
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
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	if req.Secrets[0].Account != "Default Account" {
		t.Fatalf("secret account = %q, want top-level config account", req.Secrets[0].Account)
	}
}

func TestParseExecExplicitSecretsUseConfigOnlyAccount(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	writeExecutable(t, binDir, "tool")
	writeProfileConfig(t, root, `
version: 1
account: fixture.1password.com
`)
	t.Chdir(root)
	t.Setenv("PATH", binDir)
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Explicit only",
		"--secret", "TOKEN=op://Fixture Infra/PlanetScale Slow Logs Token/credential",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	req := command.ExecRequest
	if len(req.Secrets) != 1 || req.Secrets[0].Alias != "TOKEN" {
		t.Fatalf("secrets = %+v, want TOKEN only", req.Secrets)
	}
	if req.Secrets[0].Account != "fixture.1password.com" {
		t.Fatalf("secret account = %q, want fixture.1password.com", req.Secrets[0].Account)
	}

	command, err = parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--config", filepath.Join(root, "agent-secret.yml"),
		"--reason", "Explicit config only",
		"--secret", "TOKEN=op://Fixture Infra/PlanetScale Slow Logs Token/credential",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse with explicit config returned error: %v", err)
	}
	if got := command.ExecRequest.Secrets[0].Account; got != "fixture.1password.com" {
		t.Fatalf("explicit config secret account = %q, want fixture.1password.com", got)
	}
}

func TestParseExecMergesProfileAndExplicitSecretsWithOverrides(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
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
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
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
	parser := NewParser()

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

	parser := NewParser()
	for _, tt := range []struct {
		args []string
		want Kind
	}{
		{args: []string{"daemon", "status"}, want: KindDaemonStatus},
		{args: []string{"daemon", "start"}, want: KindDaemonStart},
		{args: []string{"daemon", "stop"}, want: KindDaemonStop},
		{args: []string{"doctor"}, want: KindDoctor},
		{args: []string{"repair"}, want: KindRepair},
		{args: []string{"agent-context", "--json"}, want: KindAgentContext},
		{args: []string{"profile", "list", "--json"}, want: KindProfileList},
		{args: []string{"profile", "show", "--json"}, want: KindProfileShow},
		{args: []string{"install-cli"}, want: KindInstallCLI},
		{args: []string{"skill-install"}, want: KindSkillInstall},
		{args: []string{"--version"}, want: KindVersion},
		{args: []string{"version"}, want: KindVersion},
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

func TestParseMachineReadableFlags(t *testing.T) {
	dir := t.TempDir()
	writeExecutable(t, dir, "tool")
	parser := NewParser()

	command, err := parser.Parse([]string{
		"exec",
		"--allow-mutable-executable",
		"--dry-run",
		"--json",
		"--reuse-only",
		"--reason", "Preflight",
		"--cwd", dir,
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"./tool",
	})
	if err != nil {
		t.Fatalf("Parse exec dry-run returned error: %v", err)
	}
	if command.Kind != KindExec || !command.ExecDryRun || !command.OutputJSON || !command.ExecRequest.ReuseOnly {
		t.Fatalf("unexpected dry-run command: %+v", command)
	}

	command, err = parser.Parse([]string{"daemon", "status", "--json"})
	if err != nil {
		t.Fatalf("Parse daemon status json returned error: %v", err)
	}
	if command.Kind != KindDaemonStatus || !command.OutputJSON {
		t.Fatalf("daemon status json command = %+v", command)
	}

	command, err = parser.Parse([]string{"repair", "--json"})
	if err != nil {
		t.Fatalf("Parse repair json returned error: %v", err)
	}
	if command.Kind != KindRepair || !command.OutputJSON {
		t.Fatalf("repair json command = %+v", command)
	}

	command, err = parser.Parse([]string{"version", "--json"})
	if err != nil {
		t.Fatalf("Parse version json returned error: %v", err)
	}
	if command.Kind != KindVersion || !command.OutputJSON {
		t.Fatalf("version json command = %+v", command)
	}
}

func TestParseItemDescribeBuildsValidatedRequest(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	command, err := parser.Parse([]string{
		"item",
		"describe",
		"--account", "fixture.1password.com",
		"--format", "env-refs",
		"--prefix", "PLANETSCALE",
		"--ttl", "90s",
		"op://Fixture Infra/Beta PlanetScale Introspection Probe/*",
	})
	if err != nil {
		t.Fatalf("Parse item describe returned error: %v", err)
	}
	if command.Kind != KindItemDescribe {
		t.Fatalf("kind = %s, want %s", command.Kind, KindItemDescribe)
	}
	if command.ItemDescribeFormat != itemmetadata.FormatEnvRefs {
		t.Fatalf("format = %s, want env-refs", command.ItemDescribeFormat)
	}
	if command.ItemDescribePrefix != "PLANETSCALE" {
		t.Fatalf("prefix = %q, want PLANETSCALE", command.ItemDescribePrefix)
	}

	req := command.ItemDescribeRequest
	if req.Reason != "Inspect 1Password item metadata" {
		t.Fatalf("reason = %q", req.Reason)
	}
	if req.Account != "fixture.1password.com" {
		t.Fatalf("account = %q", req.Account)
	}
	if req.Ref.Raw != "op://Fixture Infra/Beta PlanetScale Introspection Probe" {
		t.Fatalf("ref = %#v", req.Ref)
	}
	if req.TTL != 90*time.Second {
		t.Fatalf("ttl = %s", req.TTL)
	}
	if got := strings.Join(req.Command, " "); !strings.HasPrefix(got, "agent-secret item describe ") {
		t.Fatalf("command = %q", got)
	}
	if !req.ReceivedAt.IsZero() || !req.ExpiresAt.IsZero() {
		t.Fatalf("client request should not set receipt times: %+v", req)
	}
}

func TestParseItemDescribeRejectsFieldRefs(t *testing.T) {
	t.Parallel()

	_, err := NewParser().Parse([]string{
		"item",
		"describe",
		"--account", "fixture.1password.com",
		"op://Fixture Infra/Beta PlanetScale Introspection Probe/password",
	})
	if !errors.Is(err, itemmetadata.ErrInvalidItemRef) {
		t.Fatalf("Parse item describe error = %v, want invalid item ref", err)
	}
}

func TestParseInstallCLIOptions(t *testing.T) {
	t.Parallel()

	parser := NewParser()
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

func TestParseSkillInstallOptions(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	command, err := parser.Parse([]string{"skill-install", "--skills-dir", "/tmp/skills", "--force"})
	if err != nil {
		t.Fatalf("Parse skill-install returned error: %v", err)
	}
	if command.Kind != KindSkillInstall {
		t.Fatalf("kind = %s, want %s", command.Kind, KindSkillInstall)
	}
	if command.InstallSkillOptions.SkillsDir != "/tmp/skills" {
		t.Fatalf("skills dir = %q, want /tmp/skills", command.InstallSkillOptions.SkillsDir)
	}
	if !command.InstallSkillOptions.Force {
		t.Fatal("force = false, want true")
	}
}

func TestParseSessionListDestroyAndHelp(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	listCommand, err := parser.Parse([]string{"session", "list", "--json"})
	if err != nil {
		t.Fatalf("Parse session list returned error: %v", err)
	}
	if listCommand.Kind != KindSessionList || !listCommand.OutputJSON {
		t.Fatalf("session list command = %+v", listCommand)
	}

	destroyCommand, err := parser.Parse([]string{"session", "destroy", "--json", "asess_abc123"})
	if err != nil {
		t.Fatalf("Parse session destroy returned error: %v", err)
	}
	if destroyCommand.Kind != KindSessionDestroy ||
		!destroyCommand.OutputJSON ||
		destroyCommand.SessionDestroyRequest.SessionID != "asess_abc123" {
		t.Fatalf("session destroy command = %+v", destroyCommand)
	}

	for _, args := range [][]string{
		{"session", "--help"},
		{"with-session", "--help"},
	} {
		command, err := parser.Parse(args)
		if !errors.Is(err, ErrHelpRequested) {
			t.Fatalf("Parse %v error = %v, want ErrHelpRequested", args, err)
		}
		if command.Kind != KindHelp || !strings.Contains(command.HelpText, "session") {
			t.Fatalf("help command for %v = %+v", args, command)
		}
	}
}

func TestParseSessionCreateBuildsMultiSecretBagFromProfileAndCLI(t *testing.T) {
	root := t.TempDir()
	writeProfileConfig(t, root, `
version: 1
profiles:
  deploy:
    account: Work
    reason: Deploy workflow
    ttl: 10m
    secrets:
      A_TOKEN: op://Example/A/token
      B_TOKEN: op://Example/B/token
`)
	t.Chdir(root)

	command, err := NewParser().Parse([]string{
		"session",
		"create",
		"--profile", "deploy",
		"--secret", "CLI_TOKEN=op://Example/CLI/token",
		"--max-reads", "3",
		"--json",
	})
	if err != nil {
		t.Fatalf("Parse session create returned error: %v", err)
	}
	if command.Kind != KindSessionCreate || !command.OutputJSON {
		t.Fatalf("command = %+v, want session create json", command)
	}
	req := command.SessionCreateRequest
	if req.Reason != "Deploy workflow" || req.TTL != 10*time.Minute || req.MaxReads != 3 {
		t.Fatalf("session create policy = %+v", req)
	}
	aliases := make([]string, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		aliases = append(aliases, secret.Alias)
		if secret.Account != "Work" {
			t.Fatalf("secret %s account = %q, want Work", secret.Alias, secret.Account)
		}
	}
	if strings.Join(aliases, ",") != "A_TOKEN,B_TOKEN,CLI_TOKEN" {
		t.Fatalf("secret aliases = %v", aliases)
	}
}

func TestParseWithSessionRecordsRequestedAliases(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)

	command, err := NewParser().Parse([]string{
		"with-session",
		"asess_abc123",
		"--cwd", root,
		"--only", "B_TOKEN,A_TOKEN",
		"--allow-mutable-executable",
		"--",
		"tool",
	})
	if err != nil {
		t.Fatalf("Parse with-session returned error: %v", err)
	}
	if command.Kind != KindWithSession {
		t.Fatalf("kind = %s, want with-session", command.Kind)
	}
	req := command.SessionResolveRequest
	if strings.Join(req.RequestedAliases, ",") != "A_TOKEN,B_TOKEN" {
		t.Fatalf("requested aliases = %v, want sorted A_TOKEN,B_TOKEN", req.RequestedAliases)
	}
}

func TestParseSessionRejectsInvalidForms(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	tests := []struct {
		name string
		args []string
		want error
	}{
		{name: "unknown session command", args: []string{"session", "open"}, want: ErrInvalidArguments},
		{name: "create child command", args: []string{"session", "create", "--reason", "Deploy", "--secret", "TOKEN=op://Example/Item/token", "--", "tool"}, want: ErrInvalidArguments},
		{name: "list args", args: []string{"session", "list", "asess_abc"}, want: ErrInvalidArguments},
		{name: "destroy missing id", args: []string{"session", "destroy"}, want: ErrInvalidArguments},
		{name: "destroy bad id", args: []string{"session", "destroy", "bad"}, want: request.ErrInvalidSessionID},
		{name: "with-session missing boundary", args: []string{"with-session", "asess_abc", "tool"}, want: ErrShellStringCommand},
		{name: "with-session missing command", args: []string{"with-session", "asess_abc", "--"}, want: ErrShellStringCommand},
		{name: "with-session misplaced arg", args: []string{"with-session", "asess_abc", "extra", "--", "tool"}, want: ErrInvalidArguments},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parser.Parse(tt.args)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Parse error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHelpIsDetailedAndValueFree(t *testing.T) {
	t.Parallel()

	parser := NewParser()
	tests := []struct {
		name  string
		args  []string
		wants []string
	}{
		{
			name:  "top",
			args:  []string{"--help"},
			wants: []string{"agent-secret controls", "agent-context", "exec", "session", "with-session", "item", "profile", "install-cli", "skill-install", "repair", "daemon", "doctor", "version", "desktop account"},
		},
		{
			name:  "agent-context",
			args:  []string{"agent-context", "--help"},
			wants: []string{"agent-context", "--config", "--json", "never resolves"},
		},
		{
			name:  "item",
			args:  []string{"item", "--help"},
			wants: []string{"item", "describe", "metadata", "secret values"},
		},
		{
			name:  "item describe",
			args:  []string{"item", "describe", "--help"},
			wants: []string{"--format", "env-refs", "--prefix", "metadata only", "op://vault/item"},
		},
		{
			name:  "exec",
			args:  []string{"exec", "--help"},
			wants: []string{"--reason", "--secret", "--profile", "--only", "--env-file", "--account", "include:", "account:", "default_profile", "agent-secret.yml", "--force-refresh", "--dry-run", "--reuse-only", "--allow-mutable-executable", "Default account", "audit.jsonl", "stdin", "stdout", "stderr"},
		},
		{
			name:  "session",
			args:  []string{"session", "--help"},
			wants: []string{"session create", "List active", "session destroy", "--max-reads", "with-session"},
		},
		{
			name:  "with-session",
			args:  []string{"with-session", "--help"},
			wants: []string{"with-session SESSION_ID", "--cwd", "--only", "--allow-mutable-executable", "never printed"},
		},
		{
			name:  "profile",
			args:  []string{"profile", "--help"},
			wants: []string{"profile", "list", "show", "without resolving secret values"},
		},
		{
			name:  "profile list",
			args:  []string{"profile", "list", "--help"},
			wants: []string{"profile list", "--config", "--json"},
		},
		{
			name:  "profile show",
			args:  []string{"profile", "show", "--help"},
			wants: []string{"profile show", "default_profile", "--config", "--json"},
		},
		{
			name:  "daemon",
			args:  []string{"daemon", "--help"},
			wants: []string{"daemon status", "daemon start", "daemon stop", "agent-secret repair", "in-memory"},
		},
		{
			name:  "doctor",
			args:  []string{"doctor", "--help"},
			wants: []string{"non-secret local diagnostics", "background helper", "1Password", "--json"},
		},
		{
			name:  "repair",
			args:  []string{"repair", "--help"},
			wants: []string{"background helper", "trusted old helpers", "--json"},
		},
		{
			name:  "version",
			args:  []string{"version", "--help"},
			wants: []string{"version", "--json"},
		},
		{
			name:  "install-cli",
			args:  []string{"install-cli", "--help"},
			wants: []string{"install", "command-line", "--bin-dir", "--force", "Agent Secret.app"},
		},
		{
			name:  "skill-install",
			args:  []string{"skill-install", "--help"},
			wants: []string{"install", "Agent Secret coding-agent skill", "--skills-dir", "--force", "agent-secret"},
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
		phantomSecretOnly := "--secret" + "-only"
		if strings.Contains(command.HelpText, phantomSecretOnly) {
			t.Fatalf("%s help names nonexistent %s mode", tt.name, phantomSecretOnly)
		}
	}
}

func writeExecutable(t *testing.T, dir string, name string) {
	t.Helper()

	writeExecutableBody(t, dir, name, "exit 0\n")
}

func writeExecutableBody(t *testing.T, dir string, name string, body string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: CLI parser tests need runnable fixture commands on PATH.
		t.Fatalf("write executable: %v", err)
	}
}

func writeProfileConfig(t *testing.T, dir string, contents string) {
	t.Helper()

	writeConfigFile(t, filepath.Join(dir, "agent-secret.yml"), contents)
}

func writeConfigFile(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
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
