//go:build unix

package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestConfigureDaemonProcessStartsNewSession(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(context.Background(), "agent-secretd")
	ConfigureDaemonProcess(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil, want session isolation")
	}
	if !cmd.SysProcAttr.Setsid {
		t.Fatal("SysProcAttr.Setsid = false, want true")
	}
}

func TestDaemonStartCommandUsesDirectBinaryForNonBundlePath(t *testing.T) {
	t.Parallel()

	cmd := StartCommand(context.Background(), "/tmp/agent-secretd", []string{"--socket", "/tmp/d.sock"})
	if cmd.Path != "/tmp/agent-secretd" {
		t.Fatalf("command path = %q, want direct daemon path", cmd.Path)
	}
	wantArgs := []string{"/tmp/agent-secretd", "--socket", "/tmp/d.sock"}
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
	}
}

func TestDaemonStartCommandUsesOpenForDarwinApp(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin app launch is only used on macOS")
	}
	t.Setenv("OP_ACCOUNT", "DefaultFixture")
	t.Setenv("AGENT_SECRET_1PASSWORD_ACCOUNT", "Fixture")

	cmd := StartCommand(context.Background(), "/Applications/Agent Secret.app", []string{"--socket", "/tmp/d.sock"})
	if cmd.Path != "/usr/bin/open" {
		t.Fatalf("command path = %q, want /usr/bin/open", cmd.Path)
	}
	wantArgs := []string{
		"/usr/bin/open",
		"-g",
		"-n",
		"/Applications/Agent Secret.app",
		"--env",
		"OP_ACCOUNT=DefaultFixture",
		"--env",
		"AGENT_SECRET_1PASSWORD_ACCOUNT=Fixture",
		"--args",
		"--socket",
		"/tmp/d.sock",
	}
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
	}
}

func TestDefaultDaemonPathReturnsDaemonCandidate(t *testing.T) {
	t.Parallel()

	path, err := DefaultDaemonPath()
	if err != nil {
		t.Fatalf("DefaultDaemonPath returned error: %v", err)
	}
	switch filepath.Base(path) {
	case "agent-secretd", "AgentSecretDaemon.app":
	default:
		t.Fatalf("DefaultDaemonPath = %q, want daemon binary or app candidate", path)
	}
}

func TestDaemonAppEnvironmentForwardsOnlyAccountSettings(t *testing.T) {
	t.Setenv("OP_ACCOUNT", "DefaultFixture")
	t.Setenv("AGENT_SECRET_1PASSWORD_ACCOUNT", "Fixture")
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/PoisonApprover.app")

	env := daemonAppEnvironment()
	for _, want := range []string{
		"OP_ACCOUNT=DefaultFixture",
		"AGENT_SECRET_1PASSWORD_ACCOUNT=Fixture",
	} {
		if !slices.Contains(env, want) {
			t.Fatalf("env = %q, want %q", env, want)
		}
	}
	for _, entry := range env {
		if entry == "AGENT_SECRET_APPROVER_PATH="+os.Getenv("AGENT_SECRET_APPROVER_PATH") {
			t.Fatalf("env forwarded approver override: %q", env)
		}
	}
}

func TestDaemonAppPathForBundledExecutable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	cliPath := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")
	daemonAppPath := filepath.Join(appPath, "Contents", "Library", "Helpers", "AgentSecretDaemon.app")
	if err := os.MkdirAll(filepath.Dir(cliPath), 0o750); err != nil {
		t.Fatalf("create cli dir: %v", err)
	}
	if err := os.MkdirAll(daemonAppPath, 0o750); err != nil {
		t.Fatalf("create daemon app: %v", err)
	}
	if err := os.WriteFile(cliPath, []byte("test"), 0o755); err != nil { //nolint:gosec // G306: bundled daemon path tests need a runnable CLI fixture.
		t.Fatalf("write cli: %v", err)
	}

	got, ok := daemonAppPathForExecutable(cliPath)
	if !ok || got != daemonAppPath {
		t.Fatalf("daemon app path = %q, %v, want %q, true", got, ok, daemonAppPath)
	}

	symlinkPath := filepath.Join(root, "bin", "agent-secret")
	if err := os.MkdirAll(filepath.Dir(symlinkPath), 0o750); err != nil {
		t.Fatalf("create symlink dir: %v", err)
	}
	if err := os.Symlink(cliPath, symlinkPath); err != nil {
		t.Fatalf("create cli symlink: %v", err)
	}
	resolvedDaemonAppPath, err := filepath.EvalSymlinks(daemonAppPath)
	if err != nil {
		t.Fatalf("resolve daemon app path: %v", err)
	}
	got, ok = daemonAppPathForExecutable(symlinkPath)
	if !ok || got != resolvedDaemonAppPath {
		t.Fatalf("daemon app path through symlink = %q, %v, want %q, true", got, ok, resolvedDaemonAppPath)
	}
}
