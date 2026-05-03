package request

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

func TestNewExecValidatesAndNormalizesRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir)
	receivedAt := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)

	req, err := NewExec(ExecOptions{
		Reason:     "  Run Terraform plan  ",
		Command:    []string{"tool", "plan"},
		CWD:        dir,
		Env:        []string{"PATH=" + dir, "EXISTING=value"},
		ReceivedAt: receivedAt,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Cloudflare/token", Account: " Fixture "},
			{Alias: "TOKEN_COPY", Ref: "op://Example Vault/Cloudflare/token"},
		},
		AllowMutableExecutable: true,
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
	if req.ExecutableIdentity.IsZero() {
		t.Fatal("executable identity was not captured")
	}
	if req.EnvironmentFingerprint == "" {
		t.Fatal("environment fingerprint was not captured")
	}
	if req.EnvironmentFingerprint != EnvironmentFingerprint(req.Env) {
		t.Fatalf("environment fingerprint = %q, want fingerprint of request env", req.EnvironmentFingerprint)
	}
	if len(req.Secrets) != 2 || req.Secrets[0].Ref.Raw != req.Secrets[1].Ref.Raw {
		t.Fatalf("duplicate refs with different aliases should be preserved: %+v", req.Secrets)
	}
	if req.Secrets[0].Account != "Fixture" {
		t.Fatalf("account = %q, want trimmed Fixture", req.Secrets[0].Account)
	}
}

func TestNewExecRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

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

func TestNewExecRejectsMutableExecutableByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

	_, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.AllowMutableExecutable = false
	}))
	if !errors.Is(err, ErrMutableExecutable) {
		t.Fatalf("NewExec error = %v, want %v", err, ErrMutableExecutable)
	}
}

func TestNewExecAllowsMutableExecutableWithExplicitOptIn(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

	req, err := NewExec(baseOptions(dir, "reason"))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if !req.AllowMutableExecutable {
		t.Fatal("AllowMutableExecutable = false, want explicit opt-in recorded")
	}
}

func TestNewExecAllowsSessionSocketMaxReads(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

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
	if err := os.Mkdir(binDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := writeExecutable(t, binDir)

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
	writeExecutable(t, dir)

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

func TestEnvironmentFingerprintBindsEffectiveEnvWithoutRawValues(t *testing.T) {
	t.Parallel()

	base := []string{
		"PATH=/usr/bin",
		"NODE_OPTIONS=--require ./safe.js",
		"DUP=first",
		"DUP=last",
	}
	reordered := []string{
		"DUP=first",
		"NODE_OPTIONS=--require ./safe.js",
		"PATH=/usr/bin",
		"DUP=last",
	}
	if EnvironmentFingerprint(base) != EnvironmentFingerprint(reordered) {
		t.Fatal("same effective environment produced different fingerprints")
	}

	changedValue := []string{"PATH=/usr/bin", "NODE_OPTIONS=--require ./evil.js", "DUP=last"}
	if EnvironmentFingerprint(base) == EnvironmentFingerprint(changedValue) {
		t.Fatal("changed environment value did not change fingerprint")
	}

	addedVariable := append(slices.Clone(base), "AWS_PROFILE=prod")
	if EnvironmentFingerprint(base) == EnvironmentFingerprint(addedVariable) {
		t.Fatal("added environment variable did not change fingerprint")
	}
}

func TestExecRequestJSONOmitsRawEnvironmentValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)
	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.Env = append(o.Env, "CANARY_SECRET_ENV=do-not-serialize")
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if strings.Contains(string(raw), "CANARY_SECRET_ENV") || strings.Contains(string(raw), "do-not-serialize") {
		t.Fatalf("request JSON included raw environment data: %s", raw)
	}
	if !strings.Contains(string(raw), req.EnvironmentFingerprint) {
		t.Fatalf("request JSON omitted environment fingerprint: %s", raw)
	}
}

func TestExecRequestValidateForDaemonAcceptsClientNormalizedRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.Env = append(o.Env, "TOKEN=already")
		o.OverrideEnv = true
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	req.Secrets[0].Account = "Work"
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestExecRequestValidateForDaemonRejectsFabricatedMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)
	req, err := NewExec(baseOptions(dir, "reason"))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	req.Secrets[0].Account = "Work"

	tests := []struct {
		name   string
		mutate func(*ExecRequest)
		want   error
	}{
		{name: "unnormalized reason", mutate: func(r *ExecRequest) { r.Reason = " reason " }, want: ErrInvalidReason},
		{name: "ttl outside bounds", mutate: func(r *ExecRequest) { r.TTL = time.Second }, want: ErrInvalidTTL},
		{name: "expiration mismatch", mutate: func(r *ExecRequest) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }, want: ErrInvalidTTL},
		{name: "relative cwd", mutate: func(r *ExecRequest) { r.CWD = "project" }, want: ErrInvalidRequest},
		{name: "relative resolved executable", mutate: func(r *ExecRequest) { r.ResolvedExecutable = "tool" }, want: ErrInvalidRequest},
		{name: "missing executable identity", mutate: func(r *ExecRequest) { r.ExecutableIdentity = fileidentity.Identity{} }, want: ErrInvalidRequest},
		{name: "missing environment fingerprint", mutate: func(r *ExecRequest) { r.EnvironmentFingerprint = "" }, want: ErrInvalidRequest},
		{name: "malformed environment fingerprint", mutate: func(r *ExecRequest) { r.EnvironmentFingerprint = "env-v1:not-hex" }, want: ErrInvalidRequest},
		{name: "missing command", mutate: func(r *ExecRequest) { r.Command = nil }, want: ErrInvalidCommand},
		{name: "session socket delivery", mutate: func(r *ExecRequest) {
			r.DeliveryMode = DeliverySessionSocket
			r.MaxReads = 1
		}, want: ErrInvalidDeliveryMode},
		{name: "tampered ref metadata", mutate: func(r *ExecRequest) { r.Secrets[0].Ref.Field = "other" }, want: ErrInvalidReference},
		{name: "empty account", mutate: func(r *ExecRequest) { r.Secrets[0].Account = "" }, want: ErrInvalidReference},
		{name: "blank account", mutate: func(r *ExecRequest) { r.Secrets[0].Account = " \t " }, want: ErrInvalidReference},
		{name: "unnormalized account", mutate: func(r *ExecRequest) { r.Secrets[0].Account = " Work " }, want: ErrInvalidReference},
		{name: "duplicate alias", mutate: func(r *ExecRequest) {
			r.Secrets = append(r.Secrets, r.Secrets[0])
		}, want: ErrInvalidAlias},
		{name: "unknown overridden alias", mutate: func(r *ExecRequest) {
			r.OverrideEnv = true
			r.OverriddenAliases = []string{"OTHER"}
		}, want: ErrInvalidAlias},
		{name: "override aliases without override", mutate: func(r *ExecRequest) {
			r.OverriddenAliases = []string{"TOKEN"}
		}, want: ErrInvalidAlias},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cloneRequest(req)
			tt.mutate(&got)
			if err := got.ValidateForDaemon(); !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestExecRequestExpiryUsesDaemonReceiptTTL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)
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

func TestExecRequestWithReceiptTimeRebasesExpiry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)
	clientTime := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	daemonTime := clientTime.Add(24 * time.Hour)

	req, err := NewExec(mutate(baseOptions(dir, "reason"), func(o *ExecOptions) {
		o.ReceivedAt = clientTime
		o.TTL = time.Minute
	}))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	rebased := req.WithReceiptTime(daemonTime)
	if !rebased.ReceivedAt.Equal(daemonTime) {
		t.Fatalf("received_at = %s, want %s", rebased.ReceivedAt, daemonTime)
	}
	if !rebased.ExpiresAt.Equal(daemonTime.Add(time.Minute)) {
		t.Fatalf("expires_at = %s, want %s", rebased.ExpiresAt, daemonTime.Add(time.Minute))
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
		AllowMutableExecutable: true,
	}
}

func mutate(opts ExecOptions, fn func(*ExecOptions)) ExecOptions {
	fn(&opts)
	return opts
}

func cloneRequest(req ExecRequest) ExecRequest {
	req.Command = slices.Clone(req.Command)
	req.Env = slices.Clone(req.Env)
	req.Secrets = slices.Clone(req.Secrets)
	req.OverriddenAliases = slices.Clone(req.OverriddenAliases)
	return req
}

func writeExecutable(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: request validation tests need a runnable fixture executable.
		t.Fatalf("write executable: %v", err)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
