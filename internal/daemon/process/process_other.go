//go:build !unix

package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
)

func ConfigureDaemonProcess(_ *exec.Cmd) {}

func StartCommand(ctx context.Context, path string, args []string) *exec.Cmd {
	//nolint:gosec // G204: daemon path is not environment-controlled; production control.NewManager selects bundled/current executable paths.
	return exec.CommandContext(ctx, path, args...)
}

func DefaultDaemonPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "agent-secretd"), nil
}

func DefaultDaemonAppPath() (string, bool) {
	return "", false
}
