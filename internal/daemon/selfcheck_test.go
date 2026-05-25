package daemon

import (
	"errors"
	"os"
	"testing"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

func TestExecutableSelfCheckAcceptsUnchangedExecutable(t *testing.T) {
	t.Parallel()

	executable := writeClientExecutableAt(t, t.TempDir())
	identity, err := fileidentity.Capture(executable)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}

	if err := NewExecutableSelfCheck(executable, identity)(); err != nil {
		t.Fatalf("self check returned error: %v", err)
	}
}

func TestCurrentExecutableSelfCheckAcceptsRunningTestBinary(t *testing.T) {
	t.Parallel()

	check, err := CurrentExecutableSelfCheck()
	if err != nil {
		t.Fatalf("CurrentExecutableSelfCheck returned error: %v", err)
	}
	if err := check(); err != nil {
		t.Fatalf("current executable self check returned error: %v", err)
	}
}

func TestExecutableSelfCheckRejectsMissingStartupIdentity(t *testing.T) {
	t.Parallel()

	executable := writeClientExecutableAt(t, t.TempDir())
	err := NewExecutableSelfCheck(executable, fileidentity.Identity{})()
	if !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("self check error = %v, want ErrExecutableChanged", err)
	}
}

func TestExecutableSelfCheckRejectsChangedExecutable(t *testing.T) {
	t.Parallel()

	executable := writeClientExecutableAt(t, t.TempDir())
	identity, err := fileidentity.Capture(executable)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil { //nolint:gosec // G306: daemon self-check tests need a mutated executable fixture.
		t.Fatalf("mutate executable: %v", err)
	}

	err = NewExecutableSelfCheck(executable, identity)()
	if !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("self check error = %v, want ErrExecutableChanged", err)
	}
}

func TestExecutableSelfCheckRejectsRemovedExecutable(t *testing.T) {
	t.Parallel()

	executable := writeClientExecutableAt(t, t.TempDir())
	identity, err := fileidentity.Capture(executable)
	if err != nil {
		t.Fatalf("capture executable identity: %v", err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatalf("remove executable: %v", err)
	}

	err = NewExecutableSelfCheck(executable, identity)()
	if !errors.Is(err, ErrExecutableChanged) {
		t.Fatalf("self check error = %v, want ErrExecutableChanged", err)
	}
}
