package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestTrustedDaemonPathsForDirectExecutable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-secretd")
	got := trustedDaemonPathsForPath("  " + path + "  ")
	if len(got) != 1 || got[0] != path {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, path)
	}
}

func TestTrustedDaemonPathsRejectEmptyPath(t *testing.T) {
	t.Parallel()

	if got := trustedDaemonPathsForPath(" \t "); got != nil {
		t.Fatalf("trusted daemon paths = %q, want nil", got)
	}
}

func TestTrustedDaemonPathsForAppBundleUseBundleExecutable(t *testing.T) {
	t.Parallel()

	executable := writeApproverBundle(t, t.TempDir(), DefaultApproverBundleID, "AgentSecretDaemon")
	bundlePath := filepath.Clean(filepath.Join(filepath.Dir(executable), "..", ".."))

	got := trustedDaemonPathsForPath(bundlePath)
	if len(got) != 1 || got[0] != executable {
		t.Fatalf("trusted daemon paths = %q, want [%q]", got, executable)
	}
}

func TestTrustedDaemonValidatorRejectsMissingPeerExecutable(t *testing.T) {
	t.Parallel()

	validator := NewTrustedDaemonValidator([]string{writeExecutableAt(t, t.TempDir(), "agent-secretd")})
	err := validator.ValidateDaemonPeer(peercred.Info{})
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ValidateDaemonPeer error = %v, want ErrUntrustedDaemon", err)
	}
}

func TestTrustedDaemonValidatorAllowsTrustedExecutable(t *testing.T) {
	t.Parallel()

	trusted := writeExecutableAt(t, t.TempDir(), "agent-secretd")
	validator := newTrustedDaemonValidator([]string{trusted}, "")
	if err := validator.ValidateDaemonPeer(peercred.Info{ExecutablePath: trusted}); err != nil {
		t.Fatalf("ValidateDaemonPeer returned error: %v", err)
	}
}
