//go:build !unix

package daemon

import (
	"context"
	"os/exec"
)

func configureDaemonProcess(_ *exec.Cmd) {}

func daemonStartCommand(ctx context.Context, path string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, path, args...)
}

func defaultDaemonAppPath() (string, bool) {
	return "", false
}
