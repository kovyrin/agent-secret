package bwsm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	resolver := &Resolver{Store: store, Binary: "/usr/local/bin/bws", Runner: runner}

	value, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret())
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if value != "synthetic-value" {
		t.Fatalf("value = %q", value)
	}
	if runner.binary != "/usr/local/bin/bws" {
		t.Fatalf("binary = %q", runner.binary)
	}
	if !slices.Equal(runner.args, []string{
		"secret",
		"get",
		"synthetic-secret-id",
		"--output",
		"json",
		"--color",
		"no",
	}) {
		t.Fatalf("args = %#v", runner.args)
	}
	if !containsEnv(runner.env, "BWS_ACCESS_TOKEN=synthetic-token") {
		t.Fatalf("BWS_ACCESS_TOKEN was not set in resolver env")
	}
}

func TestResolverDefaultsTokenAliasAndAddsServerURL(t *testing.T) {
	t.Parallel()

	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","value":"synthetic-value"}`)}
	resolver := &Resolver{Store: store, Runner: runner}
	secret := testBitwardenSecret()
	secret.Source = "work"
	secret.Bitwarden = request.BitwardenSource{Alias: "work", APIURL: "https://api.example.test"}

	_, err := resolver.ResolveSecret(context.Background(), secret)
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if runner.binary != resolveBWSBinary(DefaultBWSBinary, defaultCommonBWSBinaryPaths()) {
		t.Fatalf("binary = %q", runner.binary)
	}
	if !slices.Equal(runner.args, []string{
		"secret",
		"get",
		"synthetic-secret-id",
		"--output",
		"json",
		"--color",
		"no",
		"--server-url",
		"https://api.example.test",
	}) {
		t.Fatalf("args = %#v", runner.args)
	}
}

func TestResolverFallsBackToCommonBWSPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	candidate := filepath.Join(t.TempDir(), "bws")
	if err := os.WriteFile(candidate, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: fake bws executable must look runnable for fallback discovery.
		t.Fatalf("write fake bws: %v", err)
	}
	store := NewKeychainStore("test.service")
	store.backend = newMemoryKeychainBackend().backend()
	if err := store.Put(context.Background(), Token{Alias: "work", AccessToken: "synthetic-token"}); err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	runner := &recordingRunner{output: []byte(`{"object":"secret","value":"synthetic-value"}`)}
	resolver := &Resolver{
		Store:             store,
		Runner:            runner,
		CommonBinaryPaths: func() []string { return []string{candidate} },
	}

	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if runner.binary != candidate {
		t.Fatalf("binary = %q, want fallback %q", runner.binary, candidate)
	}
}

func TestResolveBWSBinaryHonorsExplicitPathAndCustomNames(t *testing.T) {
	if got := resolveBWSBinary("/custom/bin/bws", nil); got != "/custom/bin/bws" {
		t.Fatalf("explicit path = %q", got)
	}
	if got := resolveBWSBinary("custom-bws", nil); got != "custom-bws" {
		t.Fatalf("custom binary = %q", got)
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
	resolver := &Resolver{Store: store, Runner: &recordingRunner{err: runnerErr}}
	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); !errors.Is(err, runnerErr) {
		t.Fatalf("runner error = %v, want %v", err, runnerErr)
	}

	resolver.Runner = &recordingRunner{output: []byte(`{"object":"secret"}`)}
	if _, err := resolver.ResolveSecret(context.Background(), testBitwardenSecret()); !errors.Is(err, ErrInvalidBWSOutput) {
		t.Fatalf("invalid output error = %v, want ErrInvalidBWSOutput", err)
	}
}

func TestBWSEnvironmentReplacesParentToken(t *testing.T) {
	t.Setenv("BWS_ACCESS_TOKEN", "parent-token")
	t.Setenv("NO_COLOR", "already-set")

	env := bwsEnvironment("runtime-token")
	if containsEnv(env, "BWS_ACCESS_TOKEN=parent-token") {
		t.Fatal("parent BWS_ACCESS_TOKEN survived in bws environment")
	}
	if !containsEnv(env, "BWS_ACCESS_TOKEN=runtime-token") {
		t.Fatal("runtime BWS_ACCESS_TOKEN was not installed in bws environment")
	}
	if !containsEnv(env, "NO_COLOR=already-set") {
		t.Fatal("existing NO_COLOR was not preserved")
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

type recordingRunner struct {
	binary string
	args   []string
	env    []string
	output []byte
	err    error
}

func (r *recordingRunner) Run(_ context.Context, binary string, args []string, env []string) ([]byte, error) {
	r.binary = binary
	r.args = slices.Clone(args)
	r.env = slices.Clone(env)
	return slices.Clone(r.output), r.err
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
