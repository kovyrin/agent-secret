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
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o600); err != nil {
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
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o600); err != nil {
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
	assertInstallPathMode(t, filepath.Dir(result.LinkPath), 0o755)
}

func TestInstallCLIRejectsNonExecutableTarget(t *testing.T) {
	t.Parallel()

	target := filepath.Join(t.TempDir(), "agent-secret")
	if err := os.WriteFile(target, []byte("not executable"), 0o600); err != nil {
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

func TestInstallCLIRefusesExistingDifferentSymlinkWithoutForce(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	oldExecutable := writeInstallTestExecutable(t, t.TempDir())
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.Symlink(oldExecutable, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	_, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallCLI error = %v, want ErrRefuseOverwrite", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read preserved symlink: %v", err)
	}
	if target != oldExecutable {
		t.Fatalf("preserved symlink target = %q, want old executable %q", target, oldExecutable)
	}
}

func TestInstallCLIForceReplacesExistingDifferentSymlink(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	executable := writeInstallTestExecutable(t, t.TempDir())
	oldExecutable := writeInstallTestExecutable(t, t.TempDir())
	linkPath := filepath.Join(binDir, CommandName)
	if err := os.Symlink(oldExecutable, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	if _, err := InstallCLI(CLIOptions{BinDir: binDir, ExecutablePath: executable, Force: true}); err != nil {
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
	if err := os.Mkdir(filepath.Join(binDir, CommandName), 0o750); err != nil {
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

func TestInstallSkillCreatesSymlinkToBundledSkill(t *testing.T) {
	t.Parallel()

	bundle := writeInstallTestBundle(t, t.TempDir())
	executable := filepath.Join(bundle, "Contents", "Resources", "bin", "agent-secret")
	skillsDir := filepath.Join(t.TempDir(), "skills")

	result, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, ExecutablePath: executable})
	if err != nil {
		t.Fatalf("InstallSkill returned error: %v", err)
	}
	wantTarget := resolveInstallTestPath(t, filepath.Join(bundle, "Contents", "Resources", "skills", SkillName))
	if result.LinkPath != filepath.Join(skillsDir, SkillName) {
		t.Fatalf("link path = %q, want skills dir skill", result.LinkPath)
	}
	if result.TargetPath != wantTarget {
		t.Fatalf("target path = %q, want %q", result.TargetPath, wantTarget)
	}
	target, err := os.Readlink(result.LinkPath)
	if err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if target != wantTarget {
		t.Fatalf("symlink target = %q, want %q", target, wantTarget)
	}
}

func TestInstallSkillUsesExplicitSourcePath(t *testing.T) {
	t.Parallel()

	source := writeInstallTestSkill(t, t.TempDir())
	skillsDir := filepath.Join(t.TempDir(), "skills")
	result, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, SourcePath: source})
	if err != nil {
		t.Fatalf("InstallSkill returned error: %v", err)
	}
	if result.TargetPath != resolveInstallTestPath(t, source) {
		t.Fatalf("target path = %q, want explicit source", result.TargetPath)
	}
}

func TestInstallSkillUsesDefaultSkillsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	source := writeInstallTestSkill(t, t.TempDir())

	result, err := InstallSkill(SkillOptions{SourcePath: source})
	if err != nil {
		t.Fatalf("InstallSkill returned error: %v", err)
	}
	wantLinkPath := filepath.Join(home, ".agents", "skills", SkillName)
	if result.LinkPath != wantLinkPath {
		t.Fatalf("link path = %q, want %q", result.LinkPath, wantLinkPath)
	}
	assertInstallPathMode(t, filepath.Dir(result.LinkPath), 0o755)
}

func TestInstallSkillRefusesExistingRegularFileWithoutForce(t *testing.T) {
	t.Parallel()

	skillsDir := t.TempDir()
	linkPath := filepath.Join(skillsDir, SkillName)
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	_, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, SourcePath: writeInstallTestSkill(t, t.TempDir())})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallSkill error = %v, want ErrRefuseOverwrite", err)
	}
}

func TestInstallSkillForceReplacesExistingRegularFile(t *testing.T) {
	t.Parallel()

	skillsDir := t.TempDir()
	source := writeInstallTestSkill(t, t.TempDir())
	linkPath := filepath.Join(skillsDir, SkillName)
	if err := os.WriteFile(linkPath, []byte("not a symlink"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	if _, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, SourcePath: source, Force: true}); err != nil {
		t.Fatalf("InstallSkill returned error: %v", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read replacement symlink: %v", err)
	}
	if target != resolveInstallTestPath(t, source) {
		t.Fatalf("replacement symlink target = %q, want source", target)
	}
}

func TestInstallSkillRefusesExistingDifferentSymlinkWithoutForce(t *testing.T) {
	t.Parallel()

	skillsDir := t.TempDir()
	source := writeInstallTestSkill(t, t.TempDir())
	oldSource := writeInstallTestSkill(t, t.TempDir())
	linkPath := filepath.Join(skillsDir, SkillName)
	if err := os.Symlink(oldSource, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	_, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, SourcePath: source})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallSkill error = %v, want ErrRefuseOverwrite", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read preserved symlink: %v", err)
	}
	if target != oldSource {
		t.Fatalf("preserved symlink target = %q, want old source %q", target, oldSource)
	}
}

func TestInstallSkillForceReplacesExistingDifferentSymlink(t *testing.T) {
	t.Parallel()

	skillsDir := t.TempDir()
	source := writeInstallTestSkill(t, t.TempDir())
	oldSource := writeInstallTestSkill(t, t.TempDir())
	linkPath := filepath.Join(skillsDir, SkillName)
	if err := os.Symlink(oldSource, linkPath); err != nil {
		t.Fatalf("create existing symlink: %v", err)
	}

	if _, err := InstallSkill(SkillOptions{SkillsDir: skillsDir, SourcePath: source, Force: true}); err != nil {
		t.Fatalf("InstallSkill returned error: %v", err)
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("read replacement symlink: %v", err)
	}
	if target != resolveInstallTestPath(t, source) {
		t.Fatalf("replacement symlink target = %q, want source", target)
	}
}

func TestInstallSkillRejectsMissingSkillFile(t *testing.T) {
	t.Parallel()

	_, err := InstallSkill(SkillOptions{SkillsDir: filepath.Join(t.TempDir(), "skills"), SourcePath: t.TempDir()})
	if err == nil {
		t.Fatal("InstallSkill succeeded with missing SKILL.md")
	}
}

func TestInstallSkillRejectsFileSource(t *testing.T) {
	t.Parallel()

	source := filepath.Join(t.TempDir(), "agent-secret")
	if err := os.WriteFile(source, []byte("---\nname: agent-secret\n---\n"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	_, err := InstallSkill(SkillOptions{SkillsDir: filepath.Join(t.TempDir(), "skills"), SourcePath: source})
	if err == nil {
		t.Fatal("InstallSkill succeeded with file source")
	}
}

func TestInstallSkillRejectsSkillFileDirectory(t *testing.T) {
	t.Parallel()

	source := filepath.Join(t.TempDir(), SkillName)
	if err := os.MkdirAll(filepath.Join(source, "SKILL.md"), 0o750); err != nil {
		t.Fatalf("create skill file directory: %v", err)
	}

	_, err := InstallSkill(SkillOptions{SkillsDir: filepath.Join(t.TempDir(), "skills"), SourcePath: source})
	if err == nil {
		t.Fatal("InstallSkill succeeded with SKILL.md directory")
	}
}

func TestInstallSkillRejectsDirectoryAtLinkPath(t *testing.T) {
	t.Parallel()

	skillsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(skillsDir, SkillName), 0o750); err != nil {
		t.Fatalf("create existing directory: %v", err)
	}

	_, err := InstallSkill(SkillOptions{
		SkillsDir:  skillsDir,
		SourcePath: writeInstallTestSkill(t, t.TempDir()),
		Force:      true,
	})
	if !errors.Is(err, ErrRefuseOverwrite) {
		t.Fatalf("InstallSkill error = %v, want ErrRefuseOverwrite", err)
	}
}

func writeInstallTestExecutable(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, "agent-secret")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: installer tests need a runnable fixture executable.
		t.Fatalf("write executable: %v", err)
	}
	return path
}

func writeInstallTestBundle(t *testing.T, dir string) string {
	t.Helper()

	bundle := filepath.Join(dir, "Agent Secret.app")
	executableDir := filepath.Join(bundle, "Contents", "Resources", "bin")
	skillsDir := filepath.Join(bundle, "Contents", "Resources", "skills")
	if err := os.MkdirAll(executableDir, 0o750); err != nil {
		t.Fatalf("create executable dir: %v", err)
	}
	if err := os.MkdirAll(skillsDir, 0o750); err != nil {
		t.Fatalf("create skills dir: %v", err)
	}
	writeInstallTestExecutable(t, executableDir)
	writeInstallTestSkill(t, skillsDir)
	return bundle
}

func writeInstallTestSkill(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, SkillName)
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatalf("create skill dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("---\nname: agent-secret\n---\n"), 0o600); err != nil {
		t.Fatalf("write skill file: %v", err)
	}
	return path
}

func assertInstallPathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %s, want %s", path, got, want)
	}
}

func resolveInstallTestPath(t *testing.T, path string) string {
	t.Helper()

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve path %s: %v", path, err)
	}
	return resolved
}
