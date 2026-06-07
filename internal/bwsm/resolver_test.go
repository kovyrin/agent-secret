package bwsm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretref"
)

func TestNewResolverDefaults(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	resolver := NewResolver(store)
	if resolver.Store != store {
		t.Fatal("NewResolver did not retain store")
	}
	if resolver.Binary != DefaultBWSBinary {
		t.Fatalf("Binary = %q, want %q", resolver.Binary, DefaultBWSBinary)
	}
	if resolver.Runner == nil {
		t.Fatal("Runner is nil")
	}
}

func TestResolverFetchesBitwardenValueThroughBWS(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","id":"synthetic-secret-id","value":"synthetic-value"}`)}
	binary := trustedTestBWSBinary(t)
	resolver := &Resolver{Store: store, Binary: binary, Runner: runner}

	value, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret())
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if value != "synthetic-value" {
		t.Fatalf("value = %q", value)
	}
	if runner.binary != binary {
		t.Fatalf("binary = %q", runner.binary)
	}
	assertBWSSecretGetArgs(t, runner.args, "synthetic-secret-id")
	assertIsolatedBWSConfig(t, runner)
	if !containsEnv(runner.env, "BWS_ACCESS_TOKEN=synthetic-token") {
		t.Fatalf("BWS_ACCESS_TOKEN was not set in resolver env")
	}
}

func TestResolverDefaultsTokenAliasAndUsesTrustedCommonBWSPath(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","value":"synthetic-value"}`)}
	binary := trustedTestBWSBinary(t)
	resolver := &Resolver{
		Store:             store,
		Runner:            runner,
		CommonBinaryPaths: func() []string { return []string{binary} },
	}
	secret := testBitwardenSecret()
	secret.Source = "work"
	secret.Bitwarden = request.BitwardenSource{Alias: "work"}

	_, err := resolver.ResolveSecret(context.Background(), secret)
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if runner.binary != binary {
		t.Fatalf("binary = %q", runner.binary)
	}
	assertBWSSecretGetArgs(t, runner.args, "synthetic-secret-id")
}

func TestResolverRejectsCustomBitwardenEndpoints(t *testing.T) {
	t.Parallel()

	resolver := &Resolver{Store: NewKeychainStore("test.service"), Runner: &recordingRunner{}}
	secret := testBitwardenSecret()
	secret.Bitwarden.APIURL = "https://api.example.test"

	_, err := resolver.ResolveSecret(context.Background(), secret)
	if !errors.Is(err, ErrUnsupportedEndpoint) {
		t.Fatalf("ResolveSecret error = %v, want ErrUnsupportedEndpoint", err)
	}
}

func TestResolverFallsBackToTrustedCommonBWSPath(t *testing.T) {
	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","value":"synthetic-value"}`)}
	binary := trustedTestBWSBinary(t)
	resolver := &Resolver{
		Store:             store,
		Runner:            runner,
		CommonBinaryPaths: func() []string { return []string{binary} },
	}

	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if runner.binary != binary {
		t.Fatalf("binary = %q, want fallback %q", runner.binary, binary)
	}
}

func TestResolverIgnoresPATHBWS(t *testing.T) {
	pathDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pathDir, "bws"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must look runnable for PATH discovery.
		t.Fatalf("write fake bws: %v", err)
	}
	t.Setenv("PATH", pathDir)

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","value":"synthetic-value"}`)}
	binary := trustedTestBWSBinary(t)
	resolver := &Resolver{
		Store:             store,
		Runner:            runner,
		CommonBinaryPaths: func() []string { return []string{binary} },
	}

	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if runner.binary != binary {
		t.Fatalf("binary = %q, want trusted common path %q", runner.binary, binary)
	}
}

func TestResolveBWSBinaryValidatesHelperPath(t *testing.T) {
	binary := trustedTestBWSBinary(t)
	got, err := resolveBWSBinary(binary, nil, nil)
	if err != nil {
		t.Fatalf("resolveBWSBinary explicit path returned error: %v", err)
	}
	if got != binary {
		t.Fatalf("explicit path = %q, want %q", got, binary)
	}
	got, err = resolveBWSBinary(DefaultBWSBinary, []string{binary}, nil)
	if err != nil {
		t.Fatalf("resolveBWSBinary common path returned error: %v", err)
	}
	if got != binary {
		t.Fatalf("common path = %q, want %q", got, binary)
	}
	if _, err := resolveBWSBinary("custom-bws", nil, nil); !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("custom binary error = %v, want ErrBWSUnavailable", err)
	}
	if _, err := resolveBWSBinary("relative/bws", nil, nil); !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("relative binary error = %v, want ErrBWSUnavailable", err)
	}
}

func TestResolveBWSBinaryRejectsMutableHelperPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must look runnable for trust validation.
		t.Fatalf("write fake bws: %v", err)
	}

	if _, err := resolveBWSBinary(path, nil, rejectingPathVerifier{}); !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("mutable helper error = %v, want ErrBWSUnavailable", err)
	}
}

func TestResolveBWSBinaryAcceptsBitwardenSignedMutableHelperPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign identity fallback is macOS-specific")
	}

	path := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must look runnable for trust validation.
		t.Fatalf("write fake bws: %v", err)
	}

	got, err := resolveBWSBinary(path, nil, fixedTeamPathVerifier{teamID: bitwardenDeveloperIDTeamID})
	if err != nil {
		t.Fatalf("Bitwarden-signed mutable helper error = %v", err)
	}
	want, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve helper fixture: %v", err)
	}
	if got != want {
		t.Fatalf("resolved helper = %q, want %q", got, want)
	}
}

func TestResolveBWSBinaryRejectsNonBitwardenSignedMutableHelperPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign identity fallback is macOS-specific")
	}

	path := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must look runnable for trust validation.
		t.Fatalf("write fake bws: %v", err)
	}

	if _, err := resolveBWSBinary(path, nil, fixedTeamPathVerifier{teamID: "NOTBITWARDEN"}); !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("non-Bitwarden signed mutable helper error = %v, want ErrBWSUnavailable", err)
	}
}

func TestResolverSupportsArrayOutputAndEmptyValues(t *testing.T) {
	t.Parallel()

	value, err := secretValueFromBWSOutput([]byte(`[{"object":"secret","value":""}]`))
	if err != nil {
		t.Fatalf("secretValueFromBWSOutput returned error: %v", err)
	}
	if value != "" {
		t.Fatalf("value = %q, want empty", value)
	}
}

func TestResolverRejectsInvalidProviderAndMissingTokenAlias(t *testing.T) {
	t.Parallel()

	resolver := &Resolver{Store: NewKeychainStore("test.service"), Runner: &recordingRunner{}}
	_, err := resolver.ResolveSecret(context.Background(), request.Secret{
		Ref: request.SecretRef{Provider: secretref.ProviderOnePassword, Raw: "op://Example/Item/token"},
	})
	if !errors.Is(err, ErrInvalidBWSOutput) {
		t.Fatalf("unsupported provider error = %v, want ErrInvalidBWSOutput", err)
	}

	_, err = resolver.ResolveSecret(context.Background(), request.Secret{
		Ref: request.SecretRef{Provider: secretref.ProviderBitwardenSecretsManager, SecretID: "synthetic-secret-id"},
	})
	if !errors.Is(err, ErrInvalidTokenAlias) {
		t.Fatalf("missing token alias error = %v, want ErrInvalidTokenAlias", err)
	}
}

func TestResolverReturnsTokenNotFound(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	resolver := &Resolver{Store: store, Runner: &recordingRunner{}}

	_, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret())
	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("ResolveSecret error = %v, want ErrTokenNotFound", err)
	}
}

func TestResolverReturnsRunnerAndOutputErrors(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runnerErr := errors.New("bws failed")
	resolver := &Resolver{Store: store, Binary: trustedTestBWSBinary(t), Runner: &recordingRunner{err: runnerErr}}
	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); !errors.Is(err, runnerErr) {
		t.Fatalf("runner error = %v, want %v", err, runnerErr)
	}

	resolver.Runner = &recordingRunner{output: []byte(`{"object":"secret"}`)}
	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); !errors.Is(err, ErrInvalidBWSOutput) {
		t.Fatalf("invalid output error = %v, want ErrInvalidBWSOutput", err)
	}
}

func TestBWSEnvironmentUsesMinimalAllowlist(t *testing.T) {
	t.Setenv("BWS_ACCESS_TOKEN", "parent-token")
	t.Setenv("NO_COLOR", "already-set")
	t.Setenv("BWS_SERVER_URL", "https://api.example.test")
	t.Setenv("BWS_CONFIG_FILE", "/tmp/bws-config")
	t.Setenv("BWS_PROFILE", "default")

	env := bwsEnvironment("runtime-token")
	if !slices.Equal(env, []string{"BWS_ACCESS_TOKEN=runtime-token", "NO_COLOR=1"}) {
		t.Fatalf("bws env = %#v", env)
	}
	if containsEnv(env, "BWS_ACCESS_TOKEN=parent-token") ||
		containsEnv(env, "BWS_SERVER_URL=https://api.example.test") ||
		containsEnv(env, "BWS_CONFIG_FILE=/tmp/bws-config") ||
		containsEnv(env, "BWS_PROFILE=default") {
		t.Fatal("parent bws environment survived in helper environment")
	}
}

func TestSecretValueFromBWSOutputRejectsMalformedResponses(t *testing.T) {
	t.Parallel()

	for _, output := range [][]byte{
		nil,
		[]byte(`{"object":"secret"}`),
		[]byte(`[{"object":"secret","value":"one"},{"object":"secret","value":"two"}]`),
		[]byte(`[{"object":"secret"}]`),
		[]byte(`not-json`),
	} {
		if _, err := secretValueFromBWSOutput(output); !errors.Is(err, ErrInvalidBWSOutput) {
			t.Fatalf("secretValueFromBWSOutput(%q) error = %v, want ErrInvalidBWSOutput", output, err)
		}
	}
}

func TestExecCommandRunnerRunsBWSCommand(t *testing.T) {
	t.Parallel()

	script := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '{\"value\":\"runner-value\"}'\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must be runnable by this test.
		t.Fatalf("write fake bws: %v", err)
	}
	output, err := ExecCommandRunner{}.Run(context.Background(), script, []string{"secret", "get"}, []string{"BWS_ACCESS_TOKEN=synthetic"})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if string(output) != `{"value":"runner-value"}` {
		t.Fatalf("output = %q", output)
	}
}

func TestExecCommandRunnerReportsMissingAndFailedBWS(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing-bws")
	_, err := ExecCommandRunner{}.Run(context.Background(), missing, nil, nil)
	if !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("missing bws error = %v, want ErrBWSUnavailable", err)
	}

	script := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho denied >&2\nexit 7\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must be runnable by this test.
		t.Fatalf("write failing bws: %v", err)
	}
	_, err = ExecCommandRunner{}.Run(context.Background(), script, nil, nil)
	if !errors.Is(err, ErrBWSUnavailable) || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("failed bws error = %v", err)
	}
}

func TestExecCommandRunnerSanitizesRustDiagnosticBWSFailures(t *testing.T) {
	t.Parallel()

	script := filepath.Join(t.TempDir(), "bws")
	body := `#!/bin/sh
cat >&2 <<'EOF'
Error:
   0: Doesn't contain a decryption key

Location:
   crates/bws/src/main.rs:67

Backtrace omitted. Run with RUST_BACKTRACE=1 environment variable to display it.
Run with RUST_BACKTRACE=full to include source snippets.
EOF
exit 1
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must be runnable by this test.
		t.Fatalf("write failing bws: %v", err)
	}

	_, err := ExecCommandRunner{}.Run(context.Background(), script, nil, nil)
	if !errors.Is(err, ErrBWSUnavailable) {
		t.Fatalf("failed bws error = %v, want ErrBWSUnavailable", err)
	}
	if !strings.Contains(err.Error(), "Doesn't contain a decryption key") {
		t.Fatalf("failed bws error = %v, want sanitized diagnostic", err)
	}
	for _, leaked := range []string{"Location:", "crates/bws", "Backtrace", "RUST_BACKTRACE"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("failed bws error leaked %q: %v", leaked, err)
		}
	}
}

func TestBWSFailureMessagePreservesNormalColonErrors(t *testing.T) {
	t.Parallel()

	got := bwsFailureMessage("permission denied: try again\n", "exit status 1")
	if got != "permission denied: try again" {
		t.Fatalf("message = %q, want full normal error", got)
	}
}

type recordingRunner struct {
	binary        string
	args          []string
	env           []string
	configPath    string
	configContent string
	configMode    os.FileMode
	output        []byte
	err           error
}

type fixedTeamPathVerifier struct {
	teamID string
}

func (v fixedTeamPathVerifier) VerifyPath(string) (string, error) {
	return v.teamID, nil
}

type rejectingPathVerifier struct{}

func (rejectingPathVerifier) VerifyPath(string) (string, error) {
	return "", errors.New("signature rejected")
}

func (r *recordingRunner) Run(_ context.Context, binary string, args []string, env []string) ([]byte, error) {
	r.binary = binary
	r.args = slices.Clone(args)
	r.env = slices.Clone(env)
	if configPath := valueAfterFlag(args, "--config-file"); configPath != "" {
		r.configPath = configPath
		//nolint:gosec // G304: test reads the resolver-generated temporary config path captured from fake runner args.
		if content, err := os.ReadFile(configPath); err == nil {
			r.configContent = string(content)
		}
		if info, err := os.Stat(configPath); err == nil {
			r.configMode = info.Mode().Perm()
		}
	}
	return slices.Clone(r.output), r.err
}

func assertBWSSecretGetArgs(t *testing.T, args []string, secretID string) {
	t.Helper()
	if len(args) != 11 {
		t.Fatalf("args = %#v", args)
	}
	if args[0] != "--config-file" || !filepath.IsAbs(args[1]) {
		t.Fatalf("config-file args = %#v", args[:2])
	}
	want := []string{
		"--profile",
		isolatedBWSProfile,
		"secret",
		"get",
		secretID,
		"--output",
		"json",
		"--color",
		"no",
	}
	if !slices.Equal(args[2:], want) {
		t.Fatalf("args suffix = %#v, want %#v", args[2:], want)
	}
}

func assertIsolatedBWSConfig(t *testing.T, runner *recordingRunner) {
	t.Helper()
	if runner.configPath == "" {
		t.Fatal("runner did not receive an isolated bws config path")
	}
	wantContent := "[profiles.agent-secret]\nserver_base = \"https://vault.bitwarden.com\"\nstate_opt_out = \"true\"\n"
	if runner.configContent != wantContent {
		t.Fatalf("isolated bws config = %q, want %q", runner.configContent, wantContent)
	}
	if runner.configMode != 0o600 {
		t.Fatalf("isolated bws config mode = %v, want 0600", runner.configMode)
	}
	if _, err := os.Stat(runner.configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("isolated bws config cleanup error = %v, want removed", err)
	}
}

func valueAfterFlag(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func testBitwardenSecret() request.Secret {
	return request.Secret{
		Alias: "TOKEN",
		Ref: request.SecretRef{
			Raw:      "bws://synthetic-secret-id",
			Provider: secretref.ProviderBitwardenSecretsManager,
			SecretID: "synthetic-secret-id",
		},
		Source: "work-secrets",
		Bitwarden: request.BitwardenSource{
			Alias:      "work-secrets",
			TokenAlias: "work",
		},
	}
}

func containsEnv(env []string, expected string) bool {
	for _, entry := range env {
		if strings.TrimSpace(entry) == expected {
			return true
		}
	}
	return false
}

func trustedTestBWSBinary(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/bin/sh", "/usr/bin/true", "/bin/echo"} {
		path, found, err := validateTrustedBWSBinary(candidate, nil)
		if err == nil && found {
			return path
		}
	}
	t.Fatal("no trusted system executable available for bws resolver test")
	return ""
}
