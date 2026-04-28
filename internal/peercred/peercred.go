package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

var (
	ErrMissingMetadata = errors.New("missing peer metadata")
	ErrPolicyMismatch  = errors.New("peer metadata does not match policy")
	ErrUnsupportedOS   = errors.New("peer credentials are unsupported on this OS")
)

type Info struct {
	UID            int
	GID            int
	PID            int
	ExecutablePath string
	CWD            string
}

type Expected struct {
	UID            int
	GID            int
	PID            int
	ExecutablePath string
	CWD            string
}

func Inspect(conn *net.UnixConn) (Info, error) {
	if conn == nil {
		return Info{}, errors.New("unix connection is required")
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return Info{}, fmt.Errorf("get raw unix connection: %w", err)
	}

	var info Info
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		info, inspectErr = inspectFD(fd)
	}); err != nil {
		return Info{}, fmt.Errorf("inspect unix socket: %w", err)
	}
	if inspectErr != nil {
		return Info{}, inspectErr
	}

	if err := requireComplete(info); err != nil {
		return Info{}, err
	}

	return info, nil
}

func Validate(info Info, expected Expected) error {
	if err := requireComplete(info); err != nil {
		return err
	}

	if info.UID != expected.UID {
		return fmt.Errorf("%w: uid %d != %d", ErrPolicyMismatch, info.UID, expected.UID)
	}
	if info.GID != expected.GID {
		return fmt.Errorf("%w: gid %d != %d", ErrPolicyMismatch, info.GID, expected.GID)
	}
	if info.PID != expected.PID {
		return fmt.Errorf("%w: pid %d != %d", ErrPolicyMismatch, info.PID, expected.PID)
	}

	exe, err := comparablePath(info.ExecutablePath)
	if err != nil {
		return fmt.Errorf("normalize peer executable: %w", err)
	}
	wantExe, err := comparablePath(expected.ExecutablePath)
	if err != nil {
		return fmt.Errorf("normalize expected executable: %w", err)
	}
	if exe != wantExe {
		return fmt.Errorf("%w: executable %q != %q", ErrPolicyMismatch, exe, wantExe)
	}

	cwd, err := comparablePath(info.CWD)
	if err != nil {
		return fmt.Errorf("normalize peer cwd: %w", err)
	}
	wantCWD, err := comparablePath(expected.CWD)
	if err != nil {
		return fmt.Errorf("normalize expected cwd: %w", err)
	}
	if cwd != wantCWD {
		return fmt.Errorf("%w: cwd %q != %q", ErrPolicyMismatch, cwd, wantCWD)
	}

	return nil
}

func CurrentExpected() (Expected, error) {
	exe, err := os.Executable()
	if err != nil {
		return Expected{}, fmt.Errorf("get current executable: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return Expected{}, fmt.Errorf("get current cwd: %w", err)
	}

	return Expected{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            os.Getpid(),
		ExecutablePath: exe,
		CWD:            cwd,
	}, nil
}

func requireComplete(info Info) error {
	if info.UID < 0 || info.GID < 0 || info.PID <= 0 || info.ExecutablePath == "" || info.CWD == "" {
		return ErrMissingMetadata
	}

	return nil
}

func comparablePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs, nil
	}

	return resolved, nil
}
