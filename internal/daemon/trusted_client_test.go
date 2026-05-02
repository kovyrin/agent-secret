package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestTrustedExecutableValidatorMatchesComparableExecutablePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := writeExecutableAt(t, dir, "agent-secret-real")
	link := filepath.Join(dir, "agent-secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	validator := NewTrustedExecutableValidator([]string{link})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: target})
	if err != nil {
		t.Fatalf("ValidateExecPeer returned error: %v", err)
	}
}

func TestTrustedExecutableValidatorRejectsUnlistedExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	trusted := writeExecutableAt(t, dir, "agent-secret")
	other := writeExecutableAt(t, dir, "raw-client")

	validator := NewTrustedExecutableValidator([]string{trusted})
	err := validator.ValidateExecPeer(peercred.Info{ExecutablePath: other})
	if !errors.Is(err, ErrUntrustedClient) {
		t.Fatalf("expected ErrUntrustedClient, got %v", err)
	}
}
