//go:build !unix

package process

import (
	"context"
	"os/exec"
)

func ConfigureDaemonProcess(_ *exec.Cmd) {}

func StartCommand(ctx context.Context, path string, args []string) *exec.Cmd {
	//nolint:gosec // G204: daemon path is not environment-controlled; production NewManager selects bundled/current executable paths.
	return exec.CommandContext(ctx, path, args...)
}

func DefaultDaemonAppPath() (string, bool) {
	return "", false
}
