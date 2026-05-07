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
	env := []string{"PATH=" + dir, "EXISTING=value"}

	req, err := NewExec(ExecOptions{
		Reason:     "  Run Terraform plan  ",
		Command:    []string{"tool", "plan"},
		CWD:        dir,
		Env:        env,
		ReceivedAt: receivedAt,
		Secrets: []SecretSpec{
			{Alias: "TOKEN", Ref: "op://Example Vault/Cloudflare/token", Account: " Fixture "},
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
	if req.ReusableUses != DefaultReusableUses {
		t.Fatalf("reusable uses = %d, want default %d", req.ReusableUses, DefaultReusableUses)
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
	if req.EnvironmentFingerprint != EnvironmentFingerprint(env) {
		t.Fatalf("environment fingerprint = %q, want fingerprint of request env", req.EnvironmentFingerprint)
	}
	if len(req.Secrets) != 2 || req.Secrets[0].Ref.Raw != req.Secrets[1].Ref.Raw {
		t.Fatalf("duplicate refs with different aliases should be preserved: %+v", req.Secrets)
	}
	if req.Secrets[0].Account != "Fixture" {
		t.Fatalf("account = %q, want trimmed Fixture", req.Secrets[0].Account)
	}
}

func TestSecretAliasesReturnsSortedRequestAliases(t *testing.T) {
	t.Parallel()

	secrets := []Secret{
		{Alias: "Z_TOKEN"},
		{Alias: "A_TOKEN"},
		{Alias: "M_TOKEN"},
	}
	got := SecretAliases(secrets)
	want := []string{"A_TOKEN", "M_TOKEN", "Z_TOKEN"}
	if !slices.Equal(got, want) {
		t.Fatalf("SecretAliases = %v, want %v", got, want)
	}
}

func TestNewExecLeavesReceiptTimesUnsetByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)

	req, err := NewExec(baseOptions(dir, "reason"))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	if !req.ReceivedAt.IsZero() || !req.ExpiresAt.IsZero() {
		t.Fatalf("client request times = received %s expires %s, want unset", req.ReceivedAt, req.ExpiresAt)
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
		{name: "ttl too high", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.TTL = MaxRequestTTL + time.Second }), want: ErrInvalidTTL},
		{name: "reusable uses too low", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.ReusableUses = -1 }), want: ErrInvalidReusableUses},
		{name: "reusable uses too high", opts: mutate(baseOptions(dir, "reason"), func(o *ExecOptions) { o.ReusableUses = MaxReusableUses + 1 }), want: ErrInvalidReusableUses},
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
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("Unmarshal request JSON returned error: %v", err)
	}
	for _, field := range []string{
		"resolved_executable",
		"executable_identity",
		"environment_fingerprint",
		"received_at",
		"expires_at",
		"reusable_uses",
		"override_env",
		"overridden_aliases",
		"force_refresh",
	} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("request JSON omitted snake_case field %q: %s", field, raw)
		}
	}
	if _, ok := fields["ResolvedExecutable"]; ok {
		t.Fatalf("request JSON included default Go field names: %s", raw)
	}
	if _, ok := fields["Env"]; ok {
		t.Fatalf("request JSON included local launch env field: %s", raw)
	}
	if _, ok := fields["env"]; ok {
		t.Fatalf("request JSON included local launch env field: %s", raw)
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
	req = req.WithReceiptTime(time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC))
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
	req = req.WithReceiptTime(time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC))
	req.Secrets[0].Account = "Work"

	tests := []struct {
		name   string
		mutate func(*ExecRequest)
		want   error
	}{
		{name: "unnormalized reason", mutate: func(r *ExecRequest) { r.Reason = " reason " }, want: ErrInvalidReason},
		{name: "ttl outside bounds", mutate: func(r *ExecRequest) { r.TTL = time.Second }, want: ErrInvalidTTL},
		{name: "missing receipt time", mutate: func(r *ExecRequest) { r.ReceivedAt = time.Time{} }, want: ErrInvalidRequest},
		{name: "expiration mismatch", mutate: func(r *ExecRequest) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }, want: ErrInvalidTTL},
		{name: "relative cwd", mutate: func(r *ExecRequest) { r.CWD = "project" }, want: ErrInvalidRequest},
		{name: "relative resolved executable", mutate: func(r *ExecRequest) { r.ResolvedExecutable = "tool" }, want: ErrInvalidRequest},
		{name: "missing executable identity", mutate: func(r *ExecRequest) { r.ExecutableIdentity = fileidentity.Identity{} }, want: ErrInvalidRequest},
		{name: "missing environment fingerprint", mutate: func(r *ExecRequest) { r.EnvironmentFingerprint = "" }, want: ErrInvalidRequest},
		{name: "malformed environment fingerprint", mutate: func(r *ExecRequest) { r.EnvironmentFingerprint = "env-v1:not-hex" }, want: ErrInvalidRequest},
		{name: "missing command", mutate: func(r *ExecRequest) { r.Command = nil }, want: ErrInvalidCommand},
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

func TestExecRequestValidateForDaemonRejectsSymlinkMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeExecutable(t, dir)
	req, err := NewExec(baseOptions(dir, "reason"))
	if err != nil {
		t.Fatalf("NewExec returned error: %v", err)
	}
	req = req.WithReceiptTime(time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC))
	req.Secrets[0].Account = "Work"

	cwdLink := filepath.Join(t.TempDir(), "cwd-link")
	if err := os.Symlink(req.CWD, cwdLink); err != nil {
		t.Fatalf("create cwd symlink: %v", err)
	}
	executableLink := filepath.Join(t.TempDir(), "tool-link")
	if err := os.Symlink(req.ResolvedExecutable, executableLink); err != nil {
		t.Fatalf("create executable symlink: %v", err)
	}
	brokenLink := filepath.Join(t.TempDir(), "broken-link")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), brokenLink); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ExecRequest)
	}{
		{name: "cwd symlink", mutate: func(r *ExecRequest) { r.CWD = cwdLink }},
		{name: "executable symlink", mutate: func(r *ExecRequest) { r.ResolvedExecutable = executableLink }},
		{name: "broken cwd symlink", mutate: func(r *ExecRequest) { r.CWD = brokenLink }},
		{name: "broken executable symlink", mutate: func(r *ExecRequest) { r.ResolvedExecutable = brokenLink }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cloneRequest(req)
			tt.mutate(&got)
			if err := got.ValidateForDaemon(); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ValidateForDaemon error = %v, want ErrInvalidRequest", err)
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

func TestNewItemDescribeValidatesAndNormalizesRequest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir)
	receivedAt := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)

	req, err := NewItemDescribe(ItemDescribeOptions{
		Reason:             "  Inspect item metadata  ",
		CWD:                dir,
		ResolvedExecutable: bin,
		Ref:                "op://Example Vault/Deploy Token/*",
		Account:            " Work ",
		TTL:                time.Minute,
		ReceivedAt:         receivedAt,
	})
	if err != nil {
		t.Fatalf("NewItemDescribe returned error: %v", err)
	}

	if req.Reason != "Inspect item metadata" {
		t.Fatalf("reason = %q", req.Reason)
	}
	if req.Account != "Work" {
		t.Fatalf("account = %q, want Work", req.Account)
	}
	if req.Ref.Raw != "op://Example Vault/Deploy Token" ||
		req.Ref.Vault != "Example Vault" ||
		req.Ref.Item != "Deploy Token" {
		t.Fatalf("unexpected item ref: %+v", req.Ref)
	}
	if req.TTL != time.Minute {
		t.Fatalf("ttl = %s, want 1m", req.TTL)
	}
	if !req.ReceivedAt.Equal(receivedAt) || !req.ExpiresAt.Equal(receivedAt.Add(time.Minute)) {
		t.Fatalf("unexpected request times: received=%s expires=%s", req.ReceivedAt, req.ExpiresAt)
	}
	if req.ResolvedExecutable != bin {
		t.Fatalf("resolved executable = %q, want %q", req.ResolvedExecutable, bin)
	}
	wantCommand := []string{"agent-secret", "item", "describe", "op://Example Vault/Deploy Token/*"}
	if !slices.Equal(req.Command, wantCommand) {
		t.Fatalf("default command = %v, want %v", req.Command, wantCommand)
	}
	if req.Expired(receivedAt.Add(time.Minute - time.Nanosecond)) {
		t.Fatal("item describe request expired before TTL boundary")
	}
	if !req.Expired(receivedAt.Add(time.Minute)) {
		t.Fatal("item describe request did not expire at TTL boundary")
	}
	if err := req.ValidateForDaemon(); err != nil {
		t.Fatalf("ValidateForDaemon returned error: %v", err)
	}
}

func TestNewItemDescribeLeavesReceiptTimesUnsetByDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir)

	req, err := NewItemDescribe(ItemDescribeOptions{
		Reason:             "Inspect item metadata",
		CWD:                dir,
		ResolvedExecutable: bin,
		Ref:                "op://Example Vault/Deploy Token",
		Account:            "Work",
	})
	if err != nil {
		t.Fatalf("NewItemDescribe returned error: %v", err)
	}
	if req.TTL != DefaultItemDescribeTTL {
		t.Fatalf("ttl = %s, want default %s", req.TTL, DefaultItemDescribeTTL)
	}
	if !req.ReceivedAt.IsZero() || !req.ExpiresAt.IsZero() {
		t.Fatalf("client request times = received %s expires %s, want unset", req.ReceivedAt, req.ExpiresAt)
	}

	daemonTime := time.Date(2026, 4, 28, 11, 0, 0, 0, time.UTC)
	rebased := req.WithReceiptTime(daemonTime)
	if !rebased.ReceivedAt.Equal(daemonTime) || !rebased.ExpiresAt.Equal(daemonTime.Add(DefaultItemDescribeTTL)) {
		t.Fatalf("rebased times = received %s expires %s", rebased.ReceivedAt, rebased.ExpiresAt)
	}
}

func TestNewItemDescribeRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir)
	base := ItemDescribeOptions{
		Reason:             "Inspect item metadata",
		CWD:                dir,
		ResolvedExecutable: bin,
		Ref:                "op://Example Vault/Deploy Token",
		Account:            "Work",
	}
	tests := []struct {
		name string
		opts ItemDescribeOptions
		want error
	}{
		{name: "missing reason", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.Reason = "" }), want: ErrInvalidReason},
		{name: "field ref", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.Ref = "op://Example Vault/Deploy Token/password" }), want: ErrInvalidReference},
		{name: "missing account", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.Account = " \t " }), want: ErrInvalidReference},
		{name: "ttl too low", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.TTL = time.Second }), want: ErrInvalidTTL},
		{name: "ttl too high", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.TTL = MaxRequestTTL + time.Second }), want: ErrInvalidTTL},
		{name: "missing resolved executable", opts: mutateItemDescribeOptions(base, func(o *ItemDescribeOptions) { o.ResolvedExecutable = "" }), want: ErrInvalidCommand},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewItemDescribe(tt.opts)
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestItemDescribeRequestValidateForDaemonRejectsFabricatedMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := writeExecutable(t, dir)
	req, err := NewItemDescribe(ItemDescribeOptions{
		Reason:             "Inspect item metadata",
		Command:            []string{"agent-secret", "item", "describe", "op://Example Vault/Deploy Token"},
		CWD:                dir,
		ResolvedExecutable: bin,
		Ref:                "op://Example Vault/Deploy Token",
		Account:            "Work",
		TTL:                time.Minute,
	})
	if err != nil {
		t.Fatalf("NewItemDescribe returned error: %v", err)
	}
	req = req.WithReceiptTime(time.Date(2026, 4, 28, 13, 0, 0, 0, time.UTC))

	tests := []struct {
		name   string
		mutate func(*ItemDescribeRequest)
		want   error
	}{
		{name: "unnormalized reason", mutate: func(r *ItemDescribeRequest) { r.Reason = " reason " }, want: ErrInvalidReason},
		{name: "ttl outside bounds", mutate: func(r *ItemDescribeRequest) { r.TTL = time.Second }, want: ErrInvalidTTL},
		{name: "missing receipt time", mutate: func(r *ItemDescribeRequest) { r.ReceivedAt = time.Time{} }, want: ErrInvalidRequest},
		{name: "expiration mismatch", mutate: func(r *ItemDescribeRequest) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) }, want: ErrInvalidTTL},
		{name: "relative cwd", mutate: func(r *ItemDescribeRequest) { r.CWD = "project" }, want: ErrInvalidRequest},
		{name: "relative resolved executable", mutate: func(r *ItemDescribeRequest) { r.ResolvedExecutable = "tool" }, want: ErrInvalidRequest},
		{name: "missing command", mutate: func(r *ItemDescribeRequest) { r.Command = nil }, want: ErrInvalidCommand},
		{name: "tampered ref raw", mutate: func(r *ItemDescribeRequest) { r.Ref.Raw = "op://Example Vault/Deploy Token/password" }, want: ErrInvalidReference},
		{name: "tampered ref vault", mutate: func(r *ItemDescribeRequest) { r.Ref.Vault = "Other Vault" }, want: ErrInvalidReference},
		{name: "tampered ref item", mutate: func(r *ItemDescribeRequest) { r.Ref.Item = "Other Token" }, want: ErrInvalidReference},
		{name: "unnormalized ref raw", mutate: func(r *ItemDescribeRequest) { r.Ref.Raw = "op://Example Vault/Deploy Token/*" }, want: ErrInvalidReference},
		{name: "empty account", mutate: func(r *ItemDescribeRequest) { r.Account = "" }, want: ErrInvalidReference},
		{name: "blank account", mutate: func(r *ItemDescribeRequest) { r.Account = " \t " }, want: ErrInvalidReference},
		{name: "unnormalized account", mutate: func(r *ItemDescribeRequest) { r.Account = " Work " }, want: ErrInvalidReference},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cloneItemDescribeRequest(req)
			tt.mutate(&got)
			if err := got.ValidateForDaemon(); !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
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

func mutateItemDescribeOptions(opts ItemDescribeOptions, fn func(*ItemDescribeOptions)) ItemDescribeOptions {
	fn(&opts)
	return opts
}

func cloneRequest(req ExecRequest) ExecRequest {
	req.Command = slices.Clone(req.Command)
	req.Secrets = slices.Clone(req.Secrets)
	req.OverriddenAliases = slices.Clone(req.OverriddenAliases)
	return req
}

func cloneItemDescribeRequest(req ItemDescribeRequest) ItemDescribeRequest {
	req.Command = slices.Clone(req.Command)
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
