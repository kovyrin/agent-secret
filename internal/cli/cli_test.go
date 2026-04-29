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
			wants: []string{"agent-secret controls", "exec", "daemon", "doctor", "op account list"},
		},
		{
			name:  "exec",
			args:  []string{"exec", "--help"},
			wants: []string{"--reason", "--secret", "--force-refresh", "default account", "audit.jsonl", "stdout", "stderr"},
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
