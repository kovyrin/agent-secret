package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestTrustedExecutableValidatorMatchesComparableExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := writeExecutableAt(t, dir, "agent-secret-real")
	link := filepath.Join(dir, "agent-secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	validator := NewTrustedExecutableValidator([]string{link})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: target})
	if err != nil {
		t.Fatalf("ValidateExecPeer returned error: %v", err)
	}
}

func TestTrustedExecutableValidatorRejectsUnlistedExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	other := writeExecutableAt(t, dir, "raw-client")

	validator := NewTrustedExecutableValidator([]string{trusted})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: other})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
}

func TestTrustedExecutableValidatorRejectsExecutableReplacedAfterStartup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	validator := NewTrustedExecutableValidator([]string{trusted})

	if err := os.Remove(trusted); err != nil {
		t.Fatalf("remove trusted executable: %v", err)
	}
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nexit 64\n"), 0o755); err != nil { //nolint:gosec // G306: trusted-client tests need a runnable replacement executable.
		t.Fatalf("replace trusted executable: %v", err)
	}

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: trusted})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient after replacement, got %v", err)
	}
}

func TestTrustedExecutableValidatorSkipsMissingTrustedPath(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "agent-secret")
	validator := NewTrustedExecutableValidator([]string{missing})

	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: missing})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient for missing trusted path, got %v", err)
	}
}

func TestDefaultTrustedClientPathsIncludeBundledCLIForDaemonHelper(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	daemonExe := filepath.Join(
		appPath,
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
		"Contents",
		"MacOS",
		"Agent Secret",
	)
	wantCLI := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")

	got := trustedClientPathsForExecutable(daemonExe)
	if !slices.Contains(got, wantCLI) {
		t.Fatalf("trusted paths = %v, want bundled CLI %q", got, wantCLI)
	}
}

func TestDefaultTrustedClientPathsDoNotIncludeUserLocalBin(t *testing.T) {
	t.Parallel()

	daemonExe := filepath.Join(t.TempDir(), "agent-secretd")
	got := trustedClientPathsForExecutable(daemonExe)
	for _, path := range got {
		if strings.Contains(path, filepath.Join(".local", "bin", "agent-secret")) {
			t.Fatalf("trusted paths include mutable user command path: %v", got)
		}
	}
}
