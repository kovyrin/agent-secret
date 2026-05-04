package peertrust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/testsupport/appbundle"
)

func TestTrustedDaemonPathsForDirectExecutable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-secretd")
	got, err := DaemonPathsForPath("  " + path + "  ")
	if err != nil {
		t.Fatalf("DaemonPathsForPath returned error: %v", err)
	}
	if len(got) != 1 || got[0] != path {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, path)
	}
}

func TestTrustedDaemonPathsRejectEmptyPath(t *testing.T) {
	t.Parallel()

	got, err := DaemonPathsForPath(" \t ")
	if err != nil {
		t.Fatalf("DaemonPathsForPath returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("trusted daemon paths = %q, want nil", got)
	}
}

func TestTrustedDaemonPathsForAppBundleUseBundleExecutable(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), approval.DefaultApproverBundleID, "AgentSecretDaemon")
	bundlePath := filepath.Clean(filepath.Join(filepath.Dir(executable), "..", ".."))

	got, err := DaemonPathsForPath(bundlePath)
	if err != nil {
		t.Fatalf("DaemonPathsForPath returned error: %v", err)
	}
	if len(got) != 1 || got[0] != executable {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, executable)
	}
}

func TestTrustedDaemonPathsReportInvalidAppBundle(t *testing.T) {
	t.Parallel()

	bundlePath := filepath.Join(t.TempDir(), "AgentSecretDaemon.app")
	if err := os.MkdirAll(filepath.Join(bundlePath, "Contents"), 0o755); err != nil { //nolint:gosec // G301: test app bundle fixture permissions are not security-sensitive.
		t.Fatalf("mkdir app bundle: %v", err)
	}
	_, err := DaemonPathsForPath(bundlePath)
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("DaemonPathsForPath error = %v, want %v", err, ErrUntrustedDaemon)
	}
	if !strings.Contains(err.Error(), "Info.plist") {
		t.Fatalf("DaemonPathsForPath error = %q, want Info.plist context", err.Error())
	}
}

func TestDaemonValidatorRejectsMissingPeerExecutable(t *testing.T) {
	t.Parallel()

	validator := NewDaemonValidator([]string{writeExecutableAt(t, t.TempDir(), "agent-secretd")})
	err := validator.ValidateDaemonPeer(peercred.Info{})
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ValidateDaemonPeer error = %v, want ErrUntrustedDaemon", err)
	}
}

func TestDaemonValidatorReportsSkippedTrustedPathReasons(t *testing.T) {
	t.Parallel()

	missingPath := filepath.Join(t.TempDir(), "missing-agent-secretd")
	validator := NewDaemonValidator([]string{missingPath})
	err := validator.ValidateDaemonPeer(trustedDaemonPeerInfo(writeExecutableAt(t, t.TempDir(), "agent-secretd")))
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ValidateDaemonPeer error = %v, want %v", err, ErrUntrustedDaemon)
	}
	if !strings.Contains(err.Error(), missingPath) || !strings.Contains(err.Error(), "canonicalize trusted executable") {
		t.Fatalf("ValidateDaemonPeer error = %q, want skipped candidate context", err.Error())
	}
}

func TestDaemonValidatorAllowsTrustedExecutable(t *testing.T) {
	t.Parallel()

	trusted := writeExecutableAt(t, t.TempDir(), "agent-secretd")
	validator := newDaemonValidator([]string{trusted}, "")
	if err := validator.ValidateDaemonPeer(trustedDaemonPeerInfo(trusted)); err != nil {
		t.Fatalf("ValidateDaemonPeer returned error: %v", err)
	}
}

func TestDaemonValidatorRejectsDifferentUID(t *testing.T) {
	t.Parallel()

	trusted := writeExecutableAt(t, t.TempDir(), "agent-secretd")
	validator := newDaemonValidator([]string{trusted}, "")
	info := trustedDaemonPeerInfo(trusted)
	info.UID = os.Getuid() + 1

	err := validator.ValidateDaemonPeer(info)
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ValidateDaemonPeer error = %v, want ErrUntrustedDaemon", err)
	}
	if !strings.Contains(err.Error(), "uid") {
		t.Fatalf("ValidateDaemonPeer error = %q, want uid context", err)
	}
}

func TestDaemonValidatorRejectsDifferentGID(t *testing.T) {
	t.Parallel()

	trusted := writeExecutableAt(t, t.TempDir(), "agent-secretd")
	validator := newDaemonValidator([]string{trusted}, "")
	info := trustedDaemonPeerInfo(trusted)
	info.GID = os.Getgid() + 1

	err := validator.ValidateDaemonPeer(info)
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ValidateDaemonPeer error = %v, want ErrUntrustedDaemon", err)
	}
	if !strings.Contains(err.Error(), "gid") {
		t.Fatalf("ValidateDaemonPeer error = %q, want gid context", err)
	}
}

func trustedDaemonPeerInfo(executable string) peercred.Info {
	return peercred.Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            os.Getpid(),
		ExecutablePath: executable,
	}
}
