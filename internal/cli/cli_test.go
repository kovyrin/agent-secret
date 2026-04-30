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
profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
      EXTRA_TOKEN: op://Example/Extra/token
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
			wants: []string{"agent-secret controls", "exec", "daemon", "doctor", "my.1password.com"},
		},
		{
			name:  "exec",
			args:  []string{"exec", "--help"},
			wants: []string{"--reason", "--secret", "--profile", "default_profile", "agent-secret.yml", "--force-refresh", "Default account", "audit.jsonl", "stdin", "stdout", "stderr"},
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
