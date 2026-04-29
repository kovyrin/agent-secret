//go:build darwin

package execwrap

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func foregroundChild(process *os.Process, stdin io.Reader) (func() error, error) {
	file, ok := stdin.(*os.File)
	if !ok || process == nil {
		return noopTerminalRestore, nil
	}

	fd, err := fileDescriptor(file)
	if err != nil {
		return noopTerminalRestore, err
	}
	parentPgrp, terminal := terminalForegroundProcessGroup(fd)
	if !terminal {
		return noopTerminalRestore, nil
	}

	if err := setTerminalForeground(fd, process.Pid); err != nil {
		return noopTerminalRestore, fmt.Errorf("foreground child process group: %w", err)
	}

	return func() error {
		return setTerminalForeground(fd, parentPgrp)
	}, nil
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

func noopTerminalRestore() error {
	return nil
}

func setTerminalForeground(fd int, pgrp int) error {
	signal.Ignore(syscall.SIGTTOU)
	defer signal.Reset(syscall.SIGTTOU)
	return unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgrp)
}

func fileDescriptor(file *os.File) (int, error) {
	const maxInt = uintptr(^uint(0) >> 1)

	fd := file.Fd()
	if fd > maxInt {
		return 0, fmt.Errorf("file descriptor out of int range: %d", fd)
	}
	return int(fd), nil
}

func terminalForegroundProcessGroup(fd int) (int, bool) {
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return 0, false
	}
	return pgrp, true
}
