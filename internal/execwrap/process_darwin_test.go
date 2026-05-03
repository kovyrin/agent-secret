//go:build darwin

package execwrap

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestSetProcessGroupSetsChildProcessGroup(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(context.Background(), "agent-secret-test")
	setProcessGroup(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr is nil, want process group config")
	}
	if !cmd.SysProcAttr.Setpgid {
		t.Fatal("SysProcAttr.Setpgid = false, want true")
	}
}

func TestForegroundChildNoopsWithoutTerminalInputs(t *testing.T) {
	t.Parallel()

	restore, err := foregroundChild(nil, strings.NewReader(""))
	if err != nil {
		t.Fatalf("foregroundChild returned error: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore returned error: %v", err)
	}
}

func TestSignalChildNoopsForNilInputs(t *testing.T) {
	t.Parallel()

	if err := signalChild(nil, syscall.SIGTERM); err != nil {
		t.Fatalf("signalChild nil process returned error: %v", err)
	}
	if err := signalChild(&os.Process{}, nil); err != nil {
		t.Fatalf("signalChild nil signal returned error: %v", err)
	}
}

func TestFileDescriptorReturnsOpenFileDescriptor(t *testing.T) {
	t.Parallel()

	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open dev null: %v", err)
	}
	defer func() { _ = file.Close() }()

	fd, err := fileDescriptor(file)
	if err != nil {
		t.Fatalf("fileDescriptor returned error: %v", err)
	}
	if fd < 0 {
		t.Fatalf("file descriptor = %d, want non-negative", fd)
	}
}
