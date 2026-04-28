package request

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewExecValidatesAndNormalizesRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir, "tool")
	receivedAt := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)

	req, err := NewExec(ExecOptions{
		Reason:     "  Run Terraform plan  ",
		Command:    []string{"tool", "plan"},
		CWD:        dir,
		Env:        []string{"PATH=" + dir, "EXISTING=value"},
		ReceivedAt: receivedAt,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Cloudflare/token"},
			{Alias: "TOKEN_COPY", Ref: "op://Example Vault/Cloudflare/token"},
		},
	})
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}

	if req.Reason != "Run Terraform plan" {
		t.Fatalf("reason = %q", req.Reason)
	}
	if req.TTL != DefaultExecTTL {
		t.Fatalf("ttl = %s, want default %s", req.TTL, DefaultExecTTL)
	}
	if !req.ReceivedAt.Equal(receivedAt) || !req.ExpiresAt.Equal(receivedAt.Add(DefaultExecTTL)) {
		t.Fatalf("unexpected request times: received=%s expires=%s", req.ReceivedAt, req.ExpiresAt)
	}
	if req.DeliveryMode != DeliveryEnvExec {
		t.Fatalf("delivery mode = %s", req.DeliveryMode)
	}
	if req.ResolvedExecutable != bin {
		t.Fatalf("resolved executable = %q, want %q", req.ResolvedExecutable, bin)
	}
	if len(req.Secrets) != 2 || req.Secrets[0].Ref.Raw != req.Secrets[1].Ref.Raw {
		t.Fatalf("duplicate refs with different aliases should be preserved: %+v", req.Secrets)
	}
}

func TestNewExecRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "tool")

	tests := []struct {
		name string
		opts ExecOptions
		want error
	}{
		{name: "missing reason", opts: baseOptions(dir, ""), want: ErrInvalidReason},
		{name: "blank reason", opts: baseOptions(dir, " \t "), want: ErrInvalidReason},
		{name: "long reason", opts: baseOptions(dir, strings.Repeat("x", MaxReasonLength+1)), want: ErrInvalidReason},
		{name: "missing command", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.Command = nil }), want: ErrInvalidCommand},
		{name: "unresolved command", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.Command = []string{"missing"} }), want: ErrInvalidCommand},
		{name: "duplicate alias", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Secrets = append(o.Secrets, SecretSpec{Alias: "TOKEN", Ref: "op://Example Vault/Other/token"})
		}), want: ErrInvalidAlias},
		{name: "invalid alias", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Secrets[0].Alias = "lowercase"
		}), want: ErrInvalidAlias},
		{name: "missing alias", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Secrets[0].Alias = ""
		}), want: ErrInvalidAlias},
		{name: "invalid ref", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Secrets[0].Ref = "not-a-ref"
		}), want: ErrInvalidReference},
		{name: "empty ref segment", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Secrets[0].Ref = "op://Example Vault//token"
		}), want: ErrInvalidReference},
		{name: "ttl too low", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.TTL = time.Second }), want: ErrInvalidTTL},
		{name: "ttl too high", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.TTL = MaxExecTTL + time.Second }), want: ErrInvalidTTL},
		{name: "max reads on env exec", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.MaxReads = 1 }), want: ErrInvalidMaxReads},
		{name: "session max reads zero", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.DeliveryMode = DeliverySessionSocket
		}), want: ErrInvalidMaxReads},
		{name: "env conflict without override", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
			o.Env = append(o.Env, "TOKEN=already")
		}), want: ErrInvalidAlias},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewExec(tt.opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestNewExecAllowsSessionSocketMaxReads(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "tool")

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.DeliveryMode = DeliverySessionSocket
		o.MaxReads = 2
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if req.DeliveryMode != DeliverySessionSocket || req.MaxReads != 2 {
		t.Fatalf("unexpected session delivery policy: mode=%s maxReads=%d", req.DeliveryMode, req.MaxReads)
	}
}

func TestNewExecResolvesSlashPathRelativeToCWD(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := writeExecutable(t, binDir, "tool")

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.Command = []string{"./bin/tool"}
		o.Env = []string{"PATH=/nope"}
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if req.ResolvedExecutable != bin {
		t.Fatalf("resolved executable = %q, want %q", req.ResolvedExecutable, bin)
	}
}

func TestNewExecRecordsOverrideAliases(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "tool")

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.Env = append(o.Env, "TOKEN=already")
		o.OverrideEnv = true
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if len(req.OverriddenAliases) != 1 || req.OverriddenAliases[0] != "TOKEN" {
		t.Fatalf("overridden aliases = %+v", req.OverriddenAliases)
	}
}

func TestExecRequestExpiryUsesDaemonReceiptTTL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir, "tool")
	receivedAt := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.ReceivedAt = receivedAt
		o.TTL = time.Minute
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if req.Expired(receivedAt.Add(time.Minute - time.Nanosecond)) {
		t.Fatal("request expired before TTL boundary")
	}
	if !req.Expired(receivedAt.Add(time.Minute)) {
		t.Fatal("request did not expire at TTL boundary")
	}
}

func TestParseSecretRef(t *testing.T) {
	t.Parallel()

	ref, err := ParseSecretRef("op://Example Vault/Item/API/token")
	if err != nil {
		t.Fatalf("ParseSecretRef returned error: %v", err)
	}
	if ref.Vault != "Example Vault" || ref.Item != "Item" || ref.Section != "API" || ref.Field != "token" {
		t.Fatalf("unexpected parsed ref: %+v", ref)
	}
}

func baseOptions(dir string, reason string) ExecOptions {
	return ExecOptions{
		Reason:  reason,
		Command: []string{"tool"},
		CWD:     dir,
		Env:     []string{"PATH=" + dir},
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Item/token"},
		},
	}
}

func mutate(opts ExecOptions, fn func(*ExecOptions)) ExecOptions {
	fn(&opts)
	return opts
}

func writeExecutable(t *testing.T, dir string, name string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
