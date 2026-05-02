package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CommandName = "agent-secret"
const SkillName = "agent-secret"

var ErrRefuseOverwrite = errors.New("refusing to replace existing path")

type CLIOptions struct {
	BinDir         string
	ExecutablePath string
	Force          bool
}

type CLIResult struct {
	LinkPath   string
	TargetPath string
}

type SkillOptions struct {
	SkillsDir      string
	SourcePath     string
	ExecutablePath string
	Force          bool
}

type SkillResult struct {
	LinkPath   string
	TargetPath string
}

func DefaultBinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".local", "bin"), nil
}

func DefaultSkillsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".agents", "skills"), nil
}

func InstallCLI(options CLIOptions) (CLIResult, error) {
	binDir := options.BinDir
	if binDir == "" {
		var err error
		binDir, err = DefaultBinDir()
		if err != nil {
			return CLIResult{}, err
		}
	}

	targetPath := options.ExecutablePath
	if targetPath == "" {
		executable, err := os.Executable()
		if err != nil {
			return CLIResult{}, fmt.Errorf("find current executable: %w", err)
		}
		targetPath = executable
	}
	if resolved, err := filepath.EvalSymlinks(targetPath); err == nil {
		targetPath = resolved
	}
	if err := validateExecutable(targetPath); err != nil {
		return CLIResult{}, err
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil { //nolint:gosec // G301: user command directories must be searchable for PATH execution.
		return CLIResult{}, fmt.Errorf("create bin dir %s: %w", binDir, err)
	}
	linkPath := filepath.Join(binDir, CommandName)
	if err := replaceSymlink(linkPath, targetPath, options.Force); err != nil {
		return CLIResult{}, err
	}
	return CLIResult{LinkPath: linkPath, TargetPath: targetPath}, nil
}

func InstallSkill(options SkillOptions) (SkillResult, error) {
	skillsDir := options.SkillsDir
	if skillsDir == "" {
		var err error
		skillsDir, err = DefaultSkillsDir()
		if err != nil {
			return SkillResult{}, err
		}
	}

	sourcePath := options.SourcePath
	if sourcePath == "" {
		var err error
		sourcePath, err = bundledSkillPath(options.ExecutablePath)
		if err != nil {
			return SkillResult{}, err
		}
	}
	if resolved, err := filepath.EvalSymlinks(sourcePath); err == nil {
		sourcePath = resolved
	}
	if err := validateSkillDir(sourcePath); err != nil {
		return SkillResult{}, err
	}

	if err := os.MkdirAll(skillsDir, 0o755); err != nil { //nolint:gosec // G301: agent skill directories are non-secret content intended for tool discovery.
		return SkillResult{}, fmt.Errorf("create skills dir %s: %w", skillsDir, err)
	}
	linkPath := filepath.Join(skillsDir, SkillName)
	if err := replaceSymlink(linkPath, sourcePath, options.Force); err != nil {
		return SkillResult{}, err
	}
	return SkillResult{LinkPath: linkPath, TargetPath: sourcePath}, nil
}

func validateExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect executable %s: %w", path, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("executable path is not runnable: %s", path)
	}
	return nil
}

func bundledSkillPath(executablePath string) (string, error) {
	if executablePath == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("find current executable: %w", err)
		}
		executablePath = executable
	}
	if resolved, err := filepath.EvalSymlinks(executablePath); err == nil {
		executablePath = resolved
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(executablePath), "..", "skills", SkillName))
	if err := validateSkillDir(path); err != nil {
		return "", fmt.Errorf("find bundled skill relative to %s: %w", executablePath, err)
	}
	return path, nil
}

func validateSkillDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect skill directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("skill path is not a directory: %s", path)
	}
	skillFile := filepath.Join(path, "SKILL.md")
	info, err = os.Stat(skillFile)
	if err != nil {
		return fmt.Errorf("inspect skill file %s: %w", skillFile, err)
	}
	if info.IsDir() {
		return fmt.Errorf("skill file is a directory: %s", skillFile)
	}
	return nil
}

func replaceSymlink(linkPath string, targetPath string, force bool) error {
	info, err := os.Lstat(linkPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return os.Symlink(targetPath, linkPath)
		}
		return fmt.Errorf("inspect link path %s: %w", linkPath, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		if !force {
			return fmt.Errorf("%w: %s exists and is not a symlink", ErrRefuseOverwrite, linkPath)
		}
		if info.IsDir() {
			return fmt.Errorf("%w: %s is a directory", ErrRefuseOverwrite, linkPath)
		}
	} else if currentTarget, err := os.Readlink(linkPath); err == nil && currentTarget == targetPath {
		return nil
	}

	if err := os.Remove(linkPath); err != nil {
		return fmt.Errorf("remove existing link path %s: %w", linkPath, err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		return fmt.Errorf("create symlink %s -> %s: %w", linkPath, targetPath, err)
	}
	return nil
}
