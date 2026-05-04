//go:build !unix

package process

import (
	"context"
	"os/exec"
	"testing"
)

func TestConfigureDaemonProcessLeavesCommandUnchanged(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("agent-secretd")
	ConfigureDaemonProcess(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr = %#v, want nil", cmd.SysProcAttr)
	}
}

func TestDaemonStartCommandUsesDaemonPathDirectly(t *testing.T) {
	t.Parallel()

	cmd := StartCommand(context.Background(), "agent-secretd", []string{"--socket", "agent.sock"})
	wantArgs := []string{"agent-secretd", "--socket", "agent.sock"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
	}
	for i := range wantArgs {
		if cmd.Args[i] != wantArgs[i] {
			t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
		}
	}
}

func TestDefaultDaemonAppPathUnsupported(t *testing.T) {
	t.Parallel()

	if path, ok := DefaultDaemonAppPath(); ok || path != "" {
		t.Fatalf("DefaultDaemonAppPath = %q, %v; want empty false", path, ok)
	}
}
