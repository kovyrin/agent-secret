package profileconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
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

func TestLoadAppliesSessionBindingFromProfile(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  base:
    reason: Base
    session:
      bind: parent
    secrets:
      BASE_TOKEN: op://Example/Base/token
  deploy:
    include: [base]
    reason: Deploy
    session:
      bind:
        ancestor: 2
    secrets:
      DEPLOY_TOKEN: op://Example/Deploy/token
  codex:
    reason: Codex
    session:
      bind:
        ancestor_name: Codex
    secrets:
      CODEX_TOKEN: op://Example/Codex/token
  agents:
    reason: Agent wrappers
    session:
      bind:
        ancestor_names:
          - Claude
          - Codex
    secrets:
      AGENT_TOKEN: op://Example/Agent/token
`)

	base, err := Load(LoadOptions{Name: "base", StartDir: root})
	if err != nil {
		t.Fatalf("Load base returned error: %v", err)
	}
	if base.SessionBinding == nil ||
		base.SessionBinding.Mode != request.SessionBindingModeAncestor ||
		base.SessionBinding.AncestorDepth != 1 {
		t.Fatalf("base session binding = %+v", base.SessionBinding)
	}

	deploy, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if err != nil {
		t.Fatalf("Load deploy returned error: %v", err)
	}
	if deploy.SessionBinding == nil ||
		deploy.SessionBinding.Mode != request.SessionBindingModeAncestor ||
		deploy.SessionBinding.AncestorDepth != 2 {
		t.Fatalf("deploy session binding = %+v", deploy.SessionBinding)
	}

	codex, err := Load(LoadOptions{Name: "codex", StartDir: root})
	if err != nil {
		t.Fatalf("Load codex returned error: %v", err)
	}
	if codex.SessionBinding == nil ||
		codex.SessionBinding.Mode != request.SessionBindingModeAncestorName ||
		codex.SessionBinding.AncestorName != "Codex" {
		t.Fatalf("codex session binding = %+v", codex.SessionBinding)
	}
	if !slices.Equal(codex.SessionBinding.AncestorNames, []string{"Codex"}) {
		t.Fatalf("codex ancestor names = %v, want [Codex]", codex.SessionBinding.AncestorNames)
	}

	agents, err := Load(LoadOptions{Name: "agents", StartDir: root})
	if err != nil {
		t.Fatalf("Load agents returned error: %v", err)
	}
	if agents.SessionBinding == nil ||
		agents.SessionBinding.Mode != request.SessionBindingModeAncestorName ||
		agents.SessionBinding.AncestorName != "" ||
		!slices.Equal(agents.SessionBinding.AncestorNames, []string{"Claude", "Codex"}) {
		t.Fatalf("agents session binding = %+v", agents.SessionBinding)
	}

	info, err := Inspect(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	deployInfo := findProfileInfo(t, info, "deploy")
	if deployInfo.Session == nil || deployInfo.Session.Bind == nil || deployInfo.Session.Bind.AncestorDepth != 2 {
		t.Fatalf("inspect deploy session binding = %+v", deployInfo.Session)
	}
	codexInfo := findProfileInfo(t, info, "codex")
	if codexInfo.Session == nil ||
		codexInfo.Session.Bind == nil ||
		codexInfo.Session.Bind.AncestorName != "Codex" {
		t.Fatalf("inspect codex session binding = %+v", codexInfo.Session)
	}
	agentsInfo := findProfileInfo(t, info, "agents")
	if agentsInfo.Session == nil ||
		agentsInfo.Session.Bind == nil ||
		!slices.Equal(agentsInfo.Session.Bind.AncestorNames, []string{"Claude", "Codex"}) {
		t.Fatalf("inspect agents session binding = %+v", agentsInfo.Session)
	}
}

func TestLoadRejectsInvalidSessionBindingConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "unknown scalar",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind: pid
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "too deep",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor: 4
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "unknown mapping key",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        pid: 123
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "multiple mapping keys",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor: 1
        ancestor_name: zsh
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "multiple ancestor name mapping keys",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor_name: zsh
        ancestor_names: [zsh, bash]
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "bad ancestor name",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor_name: /bin/zsh
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "bad ancestor names entry",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor_names: [zsh, /bin/bash]
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
		{
			name: "empty ancestor names",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    session:
      bind:
        ancestor_names: []
    secrets:
      TOKEN: op://Example/Item/token
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			writeConfig(t, filepath.Join(root, "agent-secret.yml"), tt.config)
			_, err := Load(LoadOptions{Name: "deploy", StartDir: root})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Load error = %v, want ErrInvalidConfig", err)
			}
		})
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

func TestLoadAppliesBitwardenSourcePrecedence(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
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
      TOKEN: bws://be8e0ad8-d545-4017-a55a-b02f014d4158
      EXPLICIT:
        ref: bws://work-secrets/be8e0ad8-d545-4017-a55a-b02f014d4158
`)

	profile, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(profile.Secrets) != 2 {
		t.Fatalf("secret count = %d: %+v", len(profile.Secrets), profile.Secrets)
	}
	for _, secret := range profile.Secrets {
		if secret.Account != "" {
			t.Fatalf("%s account = %q, want empty for Bitwarden", secret.Alias, secret.Account)
		}
		if secret.Source != "work-secrets" {
			t.Fatalf("%s source = %q", secret.Alias, secret.Source)
		}
		if secret.Bitwarden.TokenAlias != "work" {
			t.Fatalf("%s token alias = %q", secret.Alias, secret.Bitwarden.TokenAlias)
		}
	}
}

func TestLoadRequiresBitwardenSourceWhenConfigIsAmbiguous(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
    personal:
      kind: secrets_manager
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://be8e0ad8-d545-4017-a55a-b02f014d4158
`)

	_, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for ambiguous Bitwarden source, got %v", err)
	}
}

func TestLoadUsesSourceQualifiedBitwardenRefWithoutTopLevelSources(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`)

	profile, err := Load(LoadOptions{Name: "deploy", StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	secret := profile.Secrets[0]
	if secret.Source != "work" || secret.Bitwarden.TokenAlias != "work" {
		t.Fatalf("Bitwarden fallback source = %+v", secret)
	}
}

func TestLoadRejectsBitwardenSourceMismatchesAndUnknownSources(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "source mismatch",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN:
        ref: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
        source: personal
`,
		},
		{
			name: "unknown source",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://personal/be8e0ad8-d545-4017-a55a-b02f014d4158
`,
		},
		{
			name: "1Password source field",
			config: `
version: 1
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN:
        ref: op://Example/Item/token
        source: work
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeConfig(t, filepath.Join(root, "agent-secret.yml"), tt.config)
			_, err := Load(LoadOptions{Name: "deploy", StartDir: root})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Load error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestLoadRejectsInvalidBitwardenSourceConfig(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "bad kind",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: password_manager
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`,
		},
		{
			name: "bad token alias",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      token_alias: bad alias
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`,
		},
		{
			name: "custom api endpoint",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      api_url: https://api.example.test
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`,
		},
		{
			name: "custom identity endpoint",
			config: `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      identity_url: https://identity.example.test
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeConfig(t, filepath.Join(root, "agent-secret.yml"), tt.config)
			_, err := Load(LoadOptions{Name: "deploy", StartDir: root})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Load error = %v, want ErrInvalidConfig", err)
			}
		})
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

func TestLoadGCPProfileWithoutSecrets(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
default_profile: beta-logs
profiles:
  beta-logs:
    reason: Inspect beta logs
    ttl: 5m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/logging.read
        - https://www.googleapis.com/auth/cloud-platform
`)

	profile, err := Load(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(profile.Secrets) != 0 {
		t.Fatalf("secrets = %+v, want none", profile.Secrets)
	}
	if profile.GCP == nil {
		t.Fatal("GCP profile missing")
	}
	if profile.GCP.GoogleAccount != "work" || profile.GCP.Project != "fixture-beta" {
		t.Fatalf("GCP access = %+v", profile.GCP)
	}
	wantScopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
		"https://www.googleapis.com/auth/logging.read",
	}
	if strings.Join(profile.GCP.Scopes, ",") != strings.Join(wantScopes, ",") {
		t.Fatalf("scopes = %v, want %v", profile.GCP.Scopes, wantScopes)
	}
}

func TestLoadGCPProfileIncludesAndOverrides(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
profiles:
  base-gcp:
    reason: Base GCP
    ttl: 10m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-readonly@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
  beta-logs:
    include:
      - base-gcp
    reason: Inspect logs
    gcp:
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/logging.read
`)

	profile, err := Load(LoadOptions{Name: "beta-logs", StartDir: root})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if profile.Reason != "Inspect logs" || profile.TTL != 10*time.Minute {
		t.Fatalf("included reason/ttl mismatch: reason=%q ttl=%s", profile.Reason, profile.TTL)
	}
	if profile.GCP == nil {
		t.Fatal("GCP profile missing")
	}
	if profile.GCP.GoogleAccount != "work" ||
		profile.GCP.Project != "fixture-beta" ||
		profile.GCP.ServiceAccount != "agent-beta-logs@fixture-beta.iam.gserviceaccount.com" {
		t.Fatalf("merged GCP = %+v", profile.GCP)
	}
	if len(profile.GCP.Scopes) != 1 || profile.GCP.Scopes[0] != "https://www.googleapis.com/auth/logging.read" {
		t.Fatalf("scopes = %v, want override logging scope", profile.GCP.Scopes)
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

func TestLoadRejectsExcessiveIncludeDepthAndCount(t *testing.T) {
	root := t.TempDir()
	var deep strings.Builder
	deep.WriteString("version: 1\nprofiles:\n")
	for index := range maxProfileIncludeDepth + 1 {
		next := index + 1
		if index == maxProfileIncludeDepth {
			writeConfigSnippetf(t, &deep, "  p%d:\n    secrets:\n      TOKEN: op://Example/Item/token\n", index)
			continue
		}
		writeConfigSnippetf(t, &deep, "  p%d:\n    include:\n      - p%d\n", index, next)
	}
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), deep.String())
	_, err := Load(LoadOptions{Name: "p0", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "include depth") {
		t.Fatalf("expected include depth ErrInvalidConfig, got %v", err)
	}

	var wide strings.Builder
	wide.WriteString("version: 1\nprofiles:\n  deploy:\n    include:\n")
	for index := range maxProfileIncludeCount + 1 {
		writeConfigSnippetf(t, &wide, "      - base%d\n", index)
	}
	for index := range maxProfileIncludeCount + 1 {
		writeConfigSnippetf(t, &wide, "  base%d:\n    secrets:\n      TOKEN_%d: op://Example/Item/token-%d\n", index, index, index)
	}
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), wide.String())
	_, err = Load(LoadOptions{Name: "deploy", StartDir: root})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "include count") {
		t.Fatalf("expected include count ErrInvalidConfig, got %v", err)
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

func TestInspectReturnsResolvedProfilesWithoutValues(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
account: Default Account
default_profile: deploy
profiles:
  base:
    reason: Base reason
    ttl: 5m
    secrets:
      BASE_TOKEN: op://Example/Base/token
  deploy:
    include:
      - base
    account: Deploy Account
    reason: Deploy reason
    secrets:
      DEPLOY_TOKEN: op://Example/Deploy/token
`)

	info, err := Inspect(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if info.SourcePath != filepath.Join(root, "agent-secret.yml") || info.DefaultProfile != "deploy" {
		t.Fatalf("unexpected config info: %+v", info)
	}
	if len(info.Profiles) != 2 || info.Profiles[0].Name != "base" || info.Profiles[1].Name != "deploy" {
		t.Fatalf("profiles not sorted: %+v", info.Profiles)
	}
	deploy := info.Profiles[1]
	if !deploy.Default || deploy.Account != "Deploy Account" || deploy.Reason != "Deploy reason" {
		t.Fatalf("deploy profile metadata mismatch: %+v", deploy)
	}
	if len(deploy.Include) != 1 || deploy.Include[0] != "base" {
		t.Fatalf("include metadata mismatch: %+v", deploy.Include)
	}
	if len(deploy.Secrets) != 2 {
		t.Fatalf("deploy secrets = %+v", deploy.Secrets)
	}
	if deploy.Secrets[0].Alias != "BASE_TOKEN" || deploy.Secrets[0].Ref != "op://Example/Base/token" {
		t.Fatalf("included secret missing: %+v", deploy.Secrets)
	}
	if deploy.Secrets[1].Alias != "DEPLOY_TOKEN" || deploy.Secrets[1].Account != "Deploy Account" {
		t.Fatalf("local secret mismatch: %+v", deploy.Secrets)
	}
}

func TestInspectReturnsBitwardenSourcesWithoutValues(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
sources:
  bitwarden:
    work:
      kind: secrets_manager
      token_alias: work-token
profiles:
  deploy:
    reason: Deploy
    secrets:
      TOKEN: bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158
`)

	info, err := Inspect(LoadOptions{StartDir: root})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	source, ok := info.Sources.Bitwarden["work"]
	if !ok {
		t.Fatalf("Bitwarden source missing from inspect output: %+v", info.Sources)
	}
	if source.TokenAlias != "work-token" || source.APIURL != "" || source.IdentityURL != "" {
		t.Fatalf("Bitwarden source metadata = %+v", source)
	}
	if info.Sources.IsZero() {
		t.Fatal("Sources.IsZero returned true for configured source")
	}
	if len(info.Profiles) != 1 || info.Profiles[0].Secrets[0].Source != "work" {
		t.Fatalf("profile secrets = %+v", info.Profiles)
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
	if !metadata.Sources.IsZero() {
		t.Fatalf("Sources = %+v, want zero", metadata.Sources)
	}
}

func TestLoadMetadataReadsBitwardenSources(t *testing.T) {
	root := t.TempDir()
	writeConfig(t, filepath.Join(root, "agent-secret.yml"), `
version: 1
account: Default Account
sources:
  bitwarden:
    work:
      kind: secrets_manager
      token_alias: work-token
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
	source, ok := metadata.Sources.Bitwarden["work"]
	if !ok {
		t.Fatalf("Bitwarden source missing: %+v", metadata.Sources)
	}
	if source.TokenAlias != "work-token" {
		t.Fatalf("token alias = %q", source.TokenAlias)
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

func TestLoadRejectsNonRegularAndOversizedConfigFiles(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "agent-secret.yml")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create fifo: %v", err)
	}
	_, err := Load(LoadOptions{Name: "one", ConfigPath: fifoPath})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file ErrInvalidConfig, got %v", err)
	}

	largePath := filepath.Join(root, "large.yml")
	if err := os.WriteFile(largePath, []byte(strings.Repeat("#", maxConfigFileBytes+1)), 0o600); err != nil {
		t.Fatalf("write large config: %v", err)
	}
	_, err = Load(LoadOptions{Name: "one", ConfigPath: largePath})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized ErrInvalidConfig, got %v", err)
	}
}

func TestFindPreservesExplicitConfigStatErrors(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(filePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := Find(filepath.Join(filePath, "agent-secret.yml"), root)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("expected stat error, got ErrConfigNotFound: %v", err)
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected wrapped stat error, got %v", err)
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

func findProfileInfo(t *testing.T, info ConfigInfo, name string) ProfileInfo {
	t.Helper()

	for _, profile := range info.Profiles {
		if profile.Name == name {
			return profile
		}
	}
	t.Fatalf("profile %q not found in %+v", name, info.Profiles)
	return ProfileInfo{}
}

func writeConfig(t *testing.T, path string, contents string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeConfigSnippetf(t *testing.T, builder *strings.Builder, format string, args ...any) {
	t.Helper()

	if _, err := fmt.Fprintf(builder, format, args...); err != nil {
		t.Fatalf("write config snippet: %v", err)
	}
}
