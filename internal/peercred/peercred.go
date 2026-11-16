package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/kovyrin/agent-secret/internal/pathresolve"
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
	PIDVersion     uint32 // Kernel process image version; changes on execve.
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

type ProcessIdentity struct {
	UID            int
	GID            int
	PID            int
	ParentPID      int
	ExecutablePath string
	StartTime      time.Time
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

// Expected returns the policy fields of the peer identity. PIDVersion is
// intentionally excluded: it identifies the process image that opened a
// connection, not the policy a requester declares for a session.
func (i Info) Expected() Expected {
	return Expected{
		UID:            i.UID,
		GID:            i.GID,
		PID:            i.PID,
		ExecutablePath: i.ExecutablePath,
		CWD:            i.CWD,
	}
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
		return fmt.Errorf("%w: normalize peer executable: %w", ErrPolicyMismatch, err)
	}
	wantExe, err := comparablePath(expected.ExecutablePath)
	if err != nil {
		return fmt.Errorf("%w: normalize expected executable: %w", ErrPolicyMismatch, err)
	}
	if exe != wantExe {
		return fmt.Errorf("%w: executable %q != %q", ErrPolicyMismatch, exe, wantExe)
	}

	cwd, err := comparablePath(info.CWD)
	if err != nil {
		return fmt.Errorf("%w: normalize peer cwd: %w", ErrPolicyMismatch, err)
	}
	wantCWD, err := comparablePath(expected.CWD)
	if err != nil {
		return fmt.Errorf("%w: normalize expected cwd: %w", ErrPolicyMismatch, err)
	}
	if cwd != wantCWD {
		return fmt.Errorf("%w: cwd %q != %q", ErrPolicyMismatch, cwd, wantCWD)
	}

	return nil
}

// ValidateConnectionPeer verifies that the peer currently visible on a
// connection is the same process image that was accepted for that connection.
// PIDs survive execve, so comparing PIDs alone lets a process stand in for the
// program that opened the connection. The kernel process identity version
// changes on execve and closes that gap.
func ValidateConnectionPeer(current Info, accepted Info) error {
	if err := requireComplete(current); err != nil {
		return err
	}
	if err := requireComplete(accepted); err != nil {
		return err
	}

	if current.UID != accepted.UID || current.GID != accepted.GID {
		return fmt.Errorf(
			"%w: peer credentials changed after connection accept: uid %d gid %d != uid %d gid %d",
			ErrPolicyMismatch,
			current.UID,
			current.GID,
			accepted.UID,
			accepted.GID,
		)
	}
	if current.PID != accepted.PID || current.PIDVersion != accepted.PIDVersion {
		return fmt.Errorf(
			"%w: peer process changed after connection accept: pid %d version %d != pid %d version %d",
			ErrPolicyMismatch,
			current.PID,
			current.PIDVersion,
			accepted.PID,
			accepted.PIDVersion,
		)
	}

	return nil
}

func CurrentExpected() (Expected, error) {
	return currentExpected(os.Executable, os.Getwd)
}

// ProcessAncestry returns the process identities observed while walking from
// pid toward its ancestors. If an ancestor cannot be inspected, the returned
// slice may be partial and still useful for callers that only need a known anchor.
func ProcessAncestry(pid int) ([]ProcessIdentity, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("%w: invalid pid %d", ErrMissingMetadata, pid)
	}
	return processAncestry(pid)
}

func currentExpected(executable func() (string, error), getwd func() (string, error)) (Expected, error) {
	exe, err := executable()
	if err != nil {
		return Expected{}, fmt.Errorf("get current executable: %w", err)
	}

	cwd, err := getwd()
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
	if info.UID < 0 || info.GID < 0 || info.PID <= 0 || info.PIDVersion == 0 ||
		info.ExecutablePath == "" || info.CWD == "" {
		return ErrMissingMetadata
	}

	return nil
}

func comparablePath(path string) (string, error) {
	return pathresolve.Strict(path)
}
