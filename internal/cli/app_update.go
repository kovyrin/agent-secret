package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/installgate"
)

const updateHelp = "Usage: agent-secret update status [--json] or agent-secret update check\n\n" +
	"Check opens Agent Secret's update window. Each installation requires approval there."

func parseUpdate(args []string) (Command, error) {
	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h", "help":
			return Command{Kind: KindHelp, HelpText: updateHelp}, ErrHelpRequested
		case "status":
			return Command{Kind: KindUpdateStatus}, nil
		case "check":
			return Command{Kind: KindUpdateCheck}, nil
		}
	}
	if len(args) == 2 && args[0] == "status" && args[1] == "--json" {
		return Command{Kind: KindUpdateStatus, OutputJSON: true}, nil
	}
	return Command{}, fmt.Errorf("%w: %s", ErrInvalidArguments, updateHelp)
}

type updateStatus struct {
	Release            string `json:"release,omitempty"`
	Build              string `json:"build,omitempty"`
	UpdaterConfigured  bool   `json:"updater_configured"`
	TransactionPresent bool   `json:"transaction_present"`
}

func installedUpdateStatus(host string) updateStatus {
	if host == "" {
		return updateStatus{}
	}
	plist := filepath.Join(host, "Contents", "Info.plist")
	invalid := errors.New("unavailable bundle metadata")
	release, _ := trust.PlistString(plist, "CFBundleShortVersionString", invalid)
	build, _ := trust.PlistString(plist, "CFBundleVersion", invalid)
	feed, _ := trust.PlistString(plist, "SUFeedURL", invalid)
	return updateStatus{
		Release: release, Build: build, UpdaterConfigured: feed != "",
		TransactionPresent: installgate.TransactionPresent(host),
	}
}

func (a App) runUpdateStatus(command Command) int {
	executable, _ := os.Executable()
	return a.writeUpdateStatus(installedUpdateStatus(installgate.HostBundle(executable)), command.OutputJSON)
}

func (a App) writeUpdateStatus(status updateStatus, outputJSON bool) int {
	if outputJSON {
		if err := json.NewEncoder(a.Stdout).Encode(status); err != nil {
			return 1
		}
		return 0
	}
	if status.Release != "" {
		a.stdoutln(fmt.Sprintf("Installed Agent Secret %s (build %s)", status.Release, status.Build))
	}
	if !status.UpdaterConfigured {
		a.stdoutln("In-app updates are unavailable for this build.")
	}
	if status.TransactionPresent {
		a.stdoutln("An update is in progress or needs recovery. Open Check for Updates for details.")
	}
	return 0
}

func (a App) runUpdateCheck(ctx context.Context) int {
	executable, _ := os.Executable()
	return a.openUpdateCheck(ctx, installgate.HostBundle(executable), openUpdateWindow)
}

func (a App) openUpdateCheck(ctx context.Context, host string, launch func(context.Context, string) error) int {
	if !installedUpdateStatus(host).UpdaterConfigured {
		a.stderrf("agent-secret: in-app updates are unavailable for this build\n")
		return 1
	}
	helper := filepath.Join(host, "Contents", "Library", "LoginItems", "AgentSecretUpdater.app")
	if err := launch(ctx, helper); err != nil {
		a.stderrf("agent-secret: could not open Check for Updates\n")
		return 1
	}
	return 0
}

func openUpdateWindow(ctx context.Context, helper string) error {
	//nolint:gosec // The helper is located relative to this bundled executable.
	cmd := exec.CommandContext(ctx, "/usr/bin/open", "-a", helper, "--args", "--check-for-updates")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd.Run()
}
