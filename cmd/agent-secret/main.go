package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/kovyrin/agent-secret/internal/cli"
	daemonapp "github.com/kovyrin/agent-secret/internal/daemon/app"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	daemonprocess "github.com/kovyrin/agent-secret/internal/daemon/process"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/installgate"
	"github.com/kovyrin/agent-secret/internal/processhardening"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == daemonprocess.AppLaunchSubcommand {
		return daemonapp.Run(args[1:], stderr)
	}

	if len(args) == 1 && args[0] == "__agent-secret-cask-postflight" {
		lease, err := installgate.RequireCaskLease()
		if err != nil {
			writeErrorf(stderr, "agent-secret: %v\n", err)
			return 1
		}
		defer func() { _ = lease.Close() }()
		result, err := install.InstallCLI(install.CLIOptions{Force: true})
		if err != nil {
			writeErrorf(stderr, "agent-secret: install CLI link: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "agent-secret command installed: %s -> %s\n", result.LinkPath, result.TargetPath)
		return 0
	}
	if len(args) == 0 || args[0] != "update" {
		lease, err := installgate.AcquireForExecutable()
		if err != nil {
			writeErrorf(stderr, "agent-secret: %v\n", err)
			return 1
		}
		if lease != nil {
			defer func() { _ = lease.Close() }()
		}
	}

	if err := processhardening.DisableCoreDumps(); err != nil {
		writeErrorf(stderr, "agent-secret: harden process: %v\n", err)
		return 1
	}

	app := cli.NewApp(func() (control.Manager, error) {
		if executable, err := os.Executable(); err == nil {
			if err := bootstrapUpdater(context.Background(), executable); err != nil {
				writeErrorf(stderr, "agent-secret: could not start background update checks; open Agent Secret to retry: %v\n", err)
			}
		}
		return newDaemonManager()
	}, stdout, stderr)
	app.DoctorApproverCheck = checkApproverHealth
	return app.Run(context.Background(), args)
}

func newDaemonManager() (control.Manager, error) {
	return control.NewManager("")
}

func checkApproverHealth(ctx context.Context) error {
	return (approval.ProcessApproverLauncher{}).CheckHealth(ctx)
}

func writeErrorf(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, format, args...)
}
