//go:build darwin

package gcpauth

import (
	"context"
	"os/exec"
)

func OpenBrowser(ctx context.Context, targetURL string) error {
	return exec.CommandContext(ctx, "/usr/bin/open", targetURL).Run() //nolint:gosec // Opens a daemon-generated OAuth URL in the user's browser.
}
