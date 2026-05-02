package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallCLICreatesSymlinkToExecutable(t *testing.T) {
	t.Parallel()

	binDir := filepath.Join(t.TempDir(), "bin")
	executable := writeInstallTestExecutable(t, t.TempDir())

	result, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable})
	if err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	wantExecutable := resolveInstallTestPath(t, executable)
	if result.LinkPath != filepath.Join(binDir, CommandName) {
		t.Fatalf("link path = %q, want bin dir command", result.LinkPath)
	}
	if result.TargetPath != wantExecutable {
		t.Fatalf("target path = %q, want executable", result.TargetPath)
	}
	target, err := os.Readlink(result.LinkPath)
	if err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if target != wantExecutable {
		t.Fatalf("symlink target = %q, want %q", target, wantExecutable)
	}
}

func TestInstallCLIResolvesExecutableSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	executable := writeInstallTestExecutable(t, dir)
	executableLink := filepath.Join(dir, "agent-secret-link")
	if err := os.Symlink(executable, executableLink); err != nil {
		t.Fatalf("create executable symlink: %v", err)
	}

	result, err := InstallCLI(CLIOptions{BinDir: filepath.Join(t.TempDir(), "bin"), ExecutablePath: executableLink})
	if err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	wantExecutable := resolveInstallTestPath(t, executable)
	if result.TargetPath != wantExecutable {
		t.Fatalf("target path = %q, want resolved executable %q", result.TargetPath, wantExecutable)
	}
}

func TestInstallCLIRefusesExistingRegularFileWithoutForce(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	_, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallCLI error = %v, want ErrRefuseOverwrite", err)
	}
}

func TestInstallCLIForceReplacesExistingRegularFile(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	if _, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable, Force: true}); err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	wantExecutable := resolveInstallTestPath(t, executable)
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read replacement symlink: %v", err)
	}
	if target != wantExecutable {
		t.Fatalf("replacement symlink target = %q, want %q", target, wantExecutable)
	}
}

func writeInstallTestExecutable(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "agent-secret")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	return path
}

func resolveInstallTestPath(t *testing.T, path string) string {
	t.Helper()

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve path %s: %v", path, err)
	}
	return resolved
}
