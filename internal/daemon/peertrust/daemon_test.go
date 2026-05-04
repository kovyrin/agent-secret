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
	got := DaemonPathsForPath("  " + path + "  ")
	if len(got) != 1 || got[0] != path {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, path)
	}
}

func TestTrustedDaemonPathsRejectEmptyPath(t *testing.T) {
	t.Parallel()

	if got := DaemonPathsForPath(" \t "); got != nil {
		t.Fatalf("trusted daemon paths = %q, want nil", got)
	}
}

func TestTrustedDaemonPathsForAppBundleUseBundleExecutable(t *testing.T) {
	t.Parallel()

	executable := appbundle.WriteApproverBundle(t, t.TempDir(), approval.DefaultApproverBundleID, "AgentSecretDaemon")
	bundlePath := filepath.Clean(filepath.Join(filepath.Dir(executable), "..", ".."))

	got := DaemonPathsForPath(bundlePath)
	if len(got) != 1 || got[0] != executable {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, executable)
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
