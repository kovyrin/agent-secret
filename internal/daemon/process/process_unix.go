//go:build unix

package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/kovyrin/agent-secret/internal/pathresolve"
)

const AppLaunchSubcommand = "__agent-secret-daemon"

func ConfigureDaemonProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func StartCommand(ctx context.Context, path string, args []string) *exec.Cmd {
	if runtime.GOOS == "darwin" && filepath.Ext(path) == ".app" {
		openArgs := []string{"-g", "-n", path}
		openArgs = append(openArgs, "--args")
		openArgs = append(openArgs, AppLaunchSubcommand)
		openArgs = append(openArgs, args...)
		//nolint:gosec // G204: open path is fixed; app path comes from control.NewManager defaults or explicit test Manager setup.
		return exec.CommandContext(ctx, "/usr/bin/open", openArgs...)
	}

	//nolint:gosec // G204: daemon path is not environment-controlled; production control.NewManager selects bundled/current executable paths.
	return exec.CommandContext(ctx, path, args...)
}

func DefaultDaemonPath() (string, error) {
	if appPath, ok := DefaultDaemonAppPath(); ok {
		return appPath, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "agent-secretd"), nil
}

func DefaultDaemonAppPath() (string, bool) {
	if runtime.GOOS != "darwin" {
		return "", false
	}
	if exe, err := os.Executable(); err == nil {
		if appPath, ok := containingDaemonAppPath(exe); ok {
			return appPath, true
		}
		if appPath, ok := daemonAppPathForExecutable(exe); ok {
			return appPath, true
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	appPath := filepath.Join(
		home,
		"Applications",
		"Agent Secret.app",
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
	)
	info, err := os.Stat(appPath)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return appPath, true
}

func containingDaemonAppPath(executable string) (string, bool) {
	candidates := []string{executable}
	if resolved := pathresolve.BestEffort(executable); resolved != executable {
		candidates = append(candidates, resolved)
	}
	for _, candidate := range candidates {
		for current := filepath.Dir(candidate); ; current = filepath.Dir(current) {
			if filepath.Base(current) == "AgentSecretDaemon.app" {
				info, err := os.Stat(current)
				if err == nil && info.IsDir() {
					return filepath.Clean(current), true
				}
				return "", false
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
		}
	}
	return "", false
}

func daemonAppPathForExecutable(executable string) (string, bool) {
	candidates := []string{executable}
	if resolved := pathresolve.BestEffort(executable); resolved != executable {
		candidates = append(candidates, resolved)
	}
	for _, candidate := range candidates {
		appPath := filepath.Clean(filepath.Join(
			filepath.Dir(candidate),
			"..",
			"..",
			"Library",
			"Helpers",
			"AgentSecretDaemon.app",
		))
		info, err := os.Stat(appPath)
		if err == nil && info.IsDir() {
			return appPath, true
		}
	}
	return "", false
}
