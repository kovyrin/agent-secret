//go:build unix

package daemon

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

func configureDaemonProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func daemonStartCommand(ctx context.Context, path string, args []string) *exec.Cmd {
	if runtime.GOOS == "darwin" && filepath.Ext(path) == ".app" {
		openArgs := []string{"-g", "-n", path}
		for _, env := range daemonAppEnvironment() {
			openArgs = append(openArgs, "--env", env)
		}
		openArgs = append(openArgs, "--args")
		openArgs = append(openArgs, args...)
		return exec.CommandContext(ctx, "/usr/bin/open", openArgs...)
	}

	return exec.CommandContext(ctx, path, args...)
}

func defaultDaemonAppPath() (string, bool) {
	if runtime.GOOS != "darwin" {
		return "", false
	}
	if appPath := os.Getenv("AGENT_SECRET_DAEMON_APP_PATH"); appPath != "" {
		return appPath, true
	}
	if exe, err := os.Executable(); err == nil {
		if appPath, ok := daemonAppPathForExecutable(exe); ok {
			return appPath, true
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	appPath := filepath.Join(home, "Applications", "AgentSecretDaemon.app")
	info, err := os.Stat(appPath)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return appPath, true
}

func daemonAppPathForExecutable(executable string) (string, bool) {
	candidates := []string{executable}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil && resolved != executable {
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

func daemonAppEnvironment() []string {
	names := []string{
		"OP_ACCOUNT",
		"AGENT_SECRET_1PASSWORD_ACCOUNT",
		"AGENT_SECRET_APPROVER_PATH",
	}
	env := make([]string, 0, len(names))
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}
