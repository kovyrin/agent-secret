package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kovyrin/agent-secret/internal/installgate"
)

// bootstrapUpdater runs only after the CLI acquired its bundle reader lease.
// The cask's link-only entry point returns before reaching this path.
func bootstrapUpdater(ctx context.Context, executable string) error {
	host := installgate.HostBundle(executable)
	if host == "" {
		return nil
	}
	app := filepath.Join(host, "Contents", "MacOS", "Agent Secret")
	bootstrapCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: the executable is in the same installed bundle as this running CLI.
	command := exec.CommandContext(bootstrapCtx, app, "--restore-background-updater")
	command.Env = []string{}
	if err := command.Run(); err != nil {
		if bootstrapCtx.Err() != nil {
			return bootstrapCtx.Err()
		}
		return err
	}
	return nil
}
