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
	"github.com/kovyrin/agent-secret/internal/processhardening"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == daemonprocess.AppLaunchSubcommand {
		return daemonapp.Run(args[1:], stderr)
	}

	if err := processhardening.DisableCoreDumps(); err != nil {
		writeErrorf(stderr, "agent-secret: harden process: %v\n", err)
		return 1
	}

	app := cli.NewApp(newDaemonManager, stdout, stderr)
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
