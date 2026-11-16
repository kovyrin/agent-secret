//go:build unix

// Package installgate coordinates bundle readers with Sparkle and Homebrew.
package installgate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/daemon/trust"
)

const markerName = ".agent-secret-update"

var (
	ErrInstallationInProgress = errors.New("installation in progress; retry when installation finishes")
	ErrRecoveryRequired       = errors.New("update recovery is pending; open Agent Secret to check recovery")
	ErrReplaced               = errors.New("the app has been replaced; retry using the installed release")
)

// AcquireForExecutable holds the stable parent of the bundle for the process
// lifetime. The app's inode can change during replacement; the parent's cannot.
//
//nolint:nilnil // Standalone binaries have no bundle directory to lock.
func AcquireForExecutable() (*os.File, error) {
	if runtime.GOOS != "darwin" || buildinfo.BundleVersion == "" {
		return nil, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return acquireForPath(executable, buildinfo.BundleVersion)
}

//nolint:nilnil // An executable outside an app has no bundle lease.
func acquireForPath(executable string, buildVersion string) (*os.File, error) {
	// os.Executable reports a resolved path on macOS. Keep the original path
	// if the bundle disappears between launch and the first filesystem access.
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	host := HostBundle(executable)
	if host == "" {
		return nil, nil
	}
	reader, err := acquire(filepath.Dir(host))
	if err != nil {
		return nil, err
	}
	version, err := trust.PlistString(filepath.Join(host, "Contents", "Info.plist"), "CFBundleVersion", ErrReplaced)
	if err != nil || version != buildVersion {
		_ = reader.Close()
		return nil, ErrReplaced
	}
	return reader, nil
}

func HostBundle(executable string) string {
	for dir := filepath.Dir(executable); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if filepath.Base(dir) == "Agent Secret.app" {
			return dir
		}
	}
	return ""
}

func TransactionPresent(host string) bool {
	_, err := os.Lstat(filepath.Join(filepath.Dir(host), markerName))
	return !errors.Is(err, os.ErrNotExist)
}

func acquire(parent string) (*os.File, error) {
	//nolint:gosec // The directory is the canonical parent of the running app; open read-only.
	dir, err := os.Open(parent)
	if err != nil {
		return nil, fmt.Errorf("open installation directory: %w", err)
	}
	if err := flock(dir, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		_ = dir.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrInstallationInProgress
		}
		return nil, fmt.Errorf("lock installation directory: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, markerName)); !errors.Is(err, os.ErrNotExist) {
		_ = dir.Close()
		return nil, ErrRecoveryRequired
	}
	return dir, nil
}

// RequireCaskLease validates the inherited writer descriptor for the single
// non-secret operation Homebrew runs before releasing its transaction.
func RequireCaskLease() (*os.File, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	host := HostBundle(executable)
	if host == "" || runtime.GOOS != "darwin" || buildinfo.BundleVersion == "" {
		return nil, ErrInstallationInProgress
	}
	lease := os.NewFile(3, "Homebrew installation directory")
	if lease == nil {
		return nil, ErrInstallationInProgress
	}
	if err := requireCaskLease(lease, filepath.Dir(host)); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

func requireCaskLease(lease *os.File, parent string) error {
	directory, err := os.Stat(parent)
	if err != nil {
		return err
	}
	current, err := lease.Stat()
	if err != nil || !current.IsDir() || !os.SameFile(current, directory) {
		return ErrInstallationInProgress
	}
	if err := flock(lease, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrInstallationInProgress
	}
	return nil
}

func flock(file *os.File, operation int) error {
	//nolint:gosec // Fd is a nonnegative Unix int descriptor from os.File.
	return unix.Flock(int(file.Fd()), operation)
}
