//go:build unix

package daemon

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"testing"
)

func TestConfigureDaemonProcessStartsNewSession(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(context.Background(), "agent-secretd")
	configureDaemonProcess(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil, want session isolation")
	}
	if !cmd.SysProcAttr.Setsid {
		t.Fatal("SysProcAttr.Setsid = false, want true")
	}
}

func TestDaemonStartCommandUsesDirectBinaryForNonBundlePath(t *testing.T) {
	t.Parallel()

	cmd := daemonStartCommand(context.Background(), "/tmp/agent-secretd", []string{"--socket", "/tmp/d.sock"})
	if cmd.Path != "/tmp/agent-secretd" {
		t.Fatalf("command path = %q, want direct daemon path", cmd.Path)
	}
	wantArgs := []string{"/tmp/agent-secretd", "--socket", "/tmp/d.sock"}
	if !slices.Equal(cmd.Args, wantArgs) {
		t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
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
