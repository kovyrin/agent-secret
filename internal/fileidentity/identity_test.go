package fileidentity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDetectsExecutableReplacement(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "echo original\n")
	identity, err := Capture(path)
	if err != nil {
		t.Fatalf("Capture returned error: %v", err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement")
	writeExecutable(t, replacement, "echo replacement\n")
	if err := os.Rename(replacement, path); err != nil {
		t.Fatalf("replace executable: %v", err)
	}

	err = Verify(path, identity)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("Verify error = %v, want %v", err, ErrMismatch)
	}
}

func TestVerifyAcceptsUnchangedExecutable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "exit 0\n")
	identity, err := Capture(path)
	if err != nil {
		t.Fatalf("Capture returned error: %v", err)
	}
	if identity.IsZero() {
		t.Fatal("Capture returned zero identity")
	}

	if err := Verify(path, identity); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
}

func TestVerifyRejectsMissingIdentity(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "exit 0\n")
	err := Verify(path, Identity{})
	if !errors.Is(err, ErrMissing) {
		t.Fatalf("Verify error = %v, want %v", err, ErrMissing)
	}
}

func TestCaptureReportsStatFailure(t *testing.T) {
	t.Parallel()

	_, err := Capture(filepath.Join(t.TempDir(), "missing-tool"))
	if err == nil {
		t.Fatal("expected missing executable error")
	}
}

func writeExecutable(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir executable dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: file identity tests need executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
}
