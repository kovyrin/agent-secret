package main

import (
	"os"

	daemonapp "github.com/kovyrin/agent-secret/internal/daemon/app"
)

func main() {
	os.Exit(daemonapp.Run(os.Args[1:], os.Stderr))
}
