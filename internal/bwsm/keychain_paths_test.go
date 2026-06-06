package bwsm

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestTrustedKeychainApplicationPathsForBundledCLI(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appRoot := filepath.Join(root, agentSecretAppBundleName)
	cliPath := filepath.Join(appRoot, "Contents", "Resources", "bin", agentSecretCLIBinaryName)
	mainExecutable := filepath.Join(appRoot, "Contents", "MacOS", agentSecretAppExecutable)
	daemonApp := filepath.Join(appRoot, "Contents", "Library", "Helpers", agentSecretDaemonBundleName)
	daemonExecutable := filepath.Join(daemonApp, "Contents", "MacOS", agentSecretAppExecutable)
	for _, path := range []string{cliPath, mainExecutable, daemonExecutable} {
		writeExecutable(t, path)
	}

	got := trustedKeychainApplicationPathsForExecutable(cliPath)
	for _, want := range []string{cliPath, daemonApp} {
		if !slices.Contains(got, want) {
			t.Fatalf("trusted paths = %v, want %q", got, want)
		}
	}
	for _, unwanted := range []string{appRoot, mainExecutable, daemonExecutable} {
		if slices.Contains(got, unwanted) {
			t.Fatalf("trusted paths = %v, did not expect %q", got, unwanted)
		}
	}
}

func TestTrustedKeychainApplicationPathsResolveSymlinkedCLI(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appRoot := filepath.Join(root, agentSecretAppBundleName)
	cliPath := filepath.Join(appRoot, "Contents", "Resources", "bin", agentSecretCLIBinaryName)
	daemonExecutable := filepath.Join(
		appRoot,
		"Contents",
		"Library",
		"Helpers",
		agentSecretDaemonBundleName,
		"Contents",
		"MacOS",
		agentSecretAppExecutable,
	)
	for _, path := range []string{cliPath, daemonExecutable} {
		writeExecutable(t, path)
	}
	symlinkPath := filepath.Join(root, "bin", agentSecretCLIBinaryName)
	if err := os.MkdirAll(filepath.Dir(symlinkPath), 0o750); err != nil {
		t.Fatalf("create symlink dir: %v", err)
	}
	if err := os.Symlink(cliPath, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	got := trustedKeychainApplicationPathsForExecutable(symlinkPath)
	resolvedCLIPath, err := filepath.EvalSymlinks(cliPath)
	if err != nil {
		t.Fatalf("resolve cli path: %v", err)
	}
	resolvedAppRoot, ok := agentSecretAppRoot(resolvedCLIPath)
	if !ok {
		t.Fatalf("resolved cli path %q is not inside app root", resolvedCLIPath)
	}
	resolvedDaemonApp := filepath.Join(
		resolvedAppRoot,
		"Contents",
		"Library",
		"Helpers",
		agentSecretDaemonBundleName,
	)
	for _, want := range []string{symlinkPath, resolvedCLIPath, resolvedDaemonApp} {
		if !slices.Contains(got, want) {
			t.Fatalf("trusted paths = %v, want %q", got, want)
		}
	}
	if slices.Contains(got, resolvedAppRoot) {
		t.Fatalf("trusted paths = %v, did not expect host app root", got)
	}
}

func TestTrustedKeychainApplicationPathsForSiblingDaemon(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cliPath := filepath.Join(root, agentSecretCLIBinaryName)
	daemonPath := filepath.Join(root, agentSecretDaemonBinaryName)
	for _, path := range []string{cliPath, daemonPath} {
		writeExecutable(t, path)
	}

	got := trustedKeychainApplicationPathsForExecutable(cliPath)
	for _, want := range []string{cliPath, daemonPath} {
		if !slices.Contains(got, want) {
			t.Fatalf("trusted paths = %v, want %q", got, want)
		}
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create executable dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write executable: %v", err)
	}
}
