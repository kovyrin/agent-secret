package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/kovyrin/agent-secret/internal/cli"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/processhardening"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if err := processhardening.DisableCoreDumps(); err != nil {
		writeErrorf(stderr, "agent-secret: harden process: %v\n", err)
		return 1
	}

	manager, err := daemon.NewManager("")
	if err != nil {
		writeErrorf(stderr, "agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	app := cli.NewApp(manager, stdout, stderr)
	return app.Run(context.Background(), args)
}

func writeErrorf(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, format, args...)
}
