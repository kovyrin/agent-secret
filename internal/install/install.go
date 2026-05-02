package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const CommandName = "agent-secret"

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

func DefaultBinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".local", "bin"), nil
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

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return CLIResult{}, fmt.Errorf("create bin dir %s: %w", binDir, err)
	}
	linkPath := filepath.Join(binDir, CommandName)
	if err := replaceSymlink(linkPath, targetPath, options.Force); err != nil {
		return CLIResult{}, err
	}
	return CLIResult{LinkPath: linkPath, TargetPath: targetPath}, nil
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
