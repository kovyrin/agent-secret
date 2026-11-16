//go:build unix

package installgate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"golang.org/x/sys/unix"
)

func TestInstallationExcludesExistingAndNewReaders(t *testing.T) {
	parent := t.TempDir()
	reader, err := acquire(parent)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := os.Open(parent) //nolint:gosec // The directory is the test's t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = installer.Close() }()
	if err := flock(installer, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("installer entered with reader active: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := flock(installer, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(parent); !errors.Is(err, ErrInstallationInProgress) {
		t.Fatalf("new reader entered during replacement: %v", err)
	}
}

func TestReaderRefusesInterruptedSparkleTransaction(t *testing.T) {
	parent := t.TempDir()
	marker := filepath.Join(parent, ".agent-secret-update")
	if err := os.Symlink("/nonexistent", marker); err != nil {
		t.Fatal(err)
	}
	if _, err := acquire(parent); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("interrupted update marker bypassed: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	reader, err := acquire(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCaskPostflightLeaseMustBeTheInstallationDirectory(t *testing.T) {
	parent := t.TempDir()
	lease, err := os.Open(parent) //nolint:gosec // The directory is the test's t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()
	if err := flock(lease, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := requireCaskLease(lease, parent); err != nil {
		t.Fatalf("owning cask lease rejected: %v", err)
	}
	if err := requireCaskLease(lease, t.TempDir()); err == nil {
		t.Fatal("lease on another directory accepted")
	}
	if _, err := acquire(parent); !errors.Is(err, ErrInstallationInProgress) {
		t.Fatalf("postflight released its parent's exclusion: %v", err)
	}
}

func TestAppReaderValidatesInstalledVersionAfterAcquiringLease(t *testing.T) {
	parent := t.TempDir()
	host := filepath.Join(parent, "Agent Secret.app")
	contents := filepath.Join(host, "Contents")
	if err := os.MkdirAll(contents, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(contents, "agent-secret")
	if err := os.WriteFile(executable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(contents, "Info.plist")
	data := []byte("<plist><dict><key>CFBundleVersion</key><string>1.0.35</string></dict></plist>")
	if err := os.WriteFile(plist, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := acquireForPath(executable, "1.0.35")
	if err != nil || reader == nil {
		t.Fatalf("expected current build to hold a lease: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireForPath(executable, "1.0.34"); !errors.Is(err, ErrReplaced) {
		t.Fatalf("stale build entered the installed bundle: %v", err)
	}
	if _, err := acquireForPath(filepath.Join(parent, "agent-secret"), "1.0.35"); err != nil {
		t.Fatalf("standalone executable needs no lease: %v", err)
	}
	if TransactionPresent(host) {
		t.Fatal("reported transaction before it began")
	}
	if err := os.WriteFile(filepath.Join(parent, markerName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !TransactionPresent(host) {
		t.Fatal("did not report interrupted transaction")
	}
	if _, err := acquireForPath(executable, "1.0.35"); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("current executable entered with a pending transaction: %v", err)
	}
}

func TestStandaloneCallDoesNotAcquireBundleLease(t *testing.T) {
	lease, err := AcquireForExecutable()
	if lease != nil || err != nil {
		t.Fatalf("standalone call returned a lease: %v", err)
	}
	if _, err := RequireCaskLease(); !errors.Is(err, ErrInstallationInProgress) {
		t.Fatalf("standalone call acquired cask privileges: %v", err)
	}
	original := buildinfo.BundleVersion
	t.Cleanup(func() { buildinfo.BundleVersion = original })
	buildinfo.BundleVersion = "1.0.35"
	lease, err = AcquireForExecutable()
	if lease != nil || err != nil {
		t.Fatalf("nonbundled executable returned a lease: %v", err)
	}
	if _, err := acquire(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acquire did not report inability to open the parent: %v", err)
	}
}
