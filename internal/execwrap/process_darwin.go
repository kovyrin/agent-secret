//go:build darwin

package execwrap

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalChild(process *os.Process, sig os.Signal) error {
	if process == nil || sig == nil {
		return nil
	}

	if signal, ok := sig.(syscall.Signal); ok {
		if err := syscall.Kill(-process.Pid, signal); err == nil {
			return nil
		}
	}

	return process.Signal(sig)
}

func terminateChild(process *os.Process) error {
	if process == nil {
		return nil
	}

	if err := signalChild(process, syscall.SIGTERM); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	return signalChild(process, syscall.SIGKILL)
}
