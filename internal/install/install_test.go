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

func TestInstallCLIUsesDefaultBinDirAndCurrentExecutable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	result, err := InstallCLI(CLIOptions{})
	if err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	wantLinkPath := filepath.Join(home, ".local", "bin", CommandName)
	if result.LinkPath != wantLinkPath {
		t.Fatalf("link path = %q, want %q", result.LinkPath, wantLinkPath)
	}
	target, err := os.Readlink(result.LinkPath)
	if err != nil {
		t.Fatalf("read default symlink: %v", err)
	}
	if target != result.TargetPath {
		t.Fatalf("symlink target = %q, want result target %q", target, result.TargetPath)
	}
}

func TestInstallCLIRejectsNonExecutableTarget(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "agent-secret")
	if err := os.WriteFile(target, []byte("not executable"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	_, err := InstallCLI(CLIOptions{BinDir: filepath.Join(t.TempDir(), "bin"), ExecutablePath: target})
	if err == nil {
		t.Fatal("InstallCLI succeeded with non-executable target")
	}
}

func TestInstallCLIRejectsDirectoryTarget(t *testing.T) {
	t.Parallel()

	_, err := InstallCLI(CLIOptions{BinDir: filepath.Join(t.TempDir(), "bin"), ExecutablePath: t.TempDir()})
	if err == nil {
		t.Fatal("InstallCLI succeeded with directory target")
	}
}

func TestInstallCLIKeepsExistingMatchingSymlink(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	resolvedExecutable := resolveInstallTestPath(t, executable)
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.Symlink(resolvedExecutable, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	if _, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable}); err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if target != resolvedExecutable {
		t.Fatalf("symlink target = %q, want %q", target, resolvedExecutable)
	}
}

func TestInstallCLIReplacesExistingDifferentSymlink(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	oldExecutable := writeInstallTestExecutable(t, t.TempDir())
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.Symlink(oldExecutable, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	if _, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable}); err != nil {
		t.Fatalf("InstallCLI returned error: %v", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read replacement symlink: %v", err)
	}
	if target != resolveInstallTestPath(t, executable) {
		t.Fatalf("replacement symlink target = %q, want executable", target)
	}
}

func TestInstallCLIForceRefusesDirectoryAtLinkPath(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(binDir, CommandName), 0o755); err != nil {
		t.Fatalf("create existing directory: %v", err)
	}

	_, err := InstallCLI(CLIOptions{
		BinDir:         binDir,
		ExecutablePath: writeInstallTestExecutable(t, t.TempDir()),
		Force:          true,
	})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallCLI error = %v, want ErrRefuseOverwrite", err)
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
