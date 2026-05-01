package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kovyrin/agent-secret/internal/cli"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/processhardening"
)

func main() {
	if err := processhardening.DisableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "agent-secret: harden process: %v\n", err)
		os.Exit(1)
	}

	manager, err := daemon.NewManager("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-secret: initialize daemon manager: %v\n", err)
		os.Exit(1)
	}
	app := cli.NewApp(manager, os.Stdout, os.Stderr)
	os.Exit(app.Run(context.Background(), os.Args[1:]))
}
