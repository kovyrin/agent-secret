//go:build !darwin

package execwrap

import (
	"os"
	"os/exec"
)

func setProcessGroup(*exec.Cmd) {}

func signalChild(process *os.Process, sig os.Signal) error {
	if process == nil || sig == nil {
		return nil
	}
	return process.Signal(sig)
}

func terminateChild(process *os.Process) error {
	if process == nil {
		return nil
	}
	return process.Kill()
}
