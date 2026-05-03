//go:build !darwin

package execwrap

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestSetProcessGroupNoopsOffDarwin(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(context.Background(), "agent-secret-test")
	setProcessGroup(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatalf("SysProcAttr = %#v, want nil", cmd.SysProcAttr)
	}
}

func TestForegroundChildNoopsOffDarwin(t *testing.T) {
	t.Parallel()

	restore, err := foregroundChild(nil, strings.NewReader(""))
	if err != nil {
		t.Fatalf("foregroundChild returned error: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore returned error: %v", err)
	}
}

func TestSignalChildNoopsForNilInputsOffDarwin(t *testing.T) {
	t.Parallel()

	if err := signalChild(nil, syscall.SIGTERM); err != nil {
		t.Fatalf("signalChild nil process returned error: %v", err)
	}
	if err := signalChild(&os.Process{}, nil); err != nil {
		t.Fatalf("signalChild nil signal returned error: %v", err)
	}
}
