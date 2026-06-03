package executabletrust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateStableExecutableRejectsUserOwnedExecutable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	executable := filepath.Join(dir, "tool")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o555); err != nil { //nolint:gosec // executable trust tests need runnable fixtures.
		t.Fatalf("write executable: %v", err)
	}

	err := ValidateStableExecutable(executable)
	if !errors.Is(err, ErrMutablePath) {
		t.Fatalf("ValidateStableExecutable error = %v, want ErrMutablePath", err)
	}
}

func TestValidateStableExecutableAcceptsSystemExecutable(t *testing.T) {
	t.Parallel()

	if err := ValidateStableExecutable("/bin/sh"); err != nil {
		t.Fatalf("ValidateStableExecutable returned error: %v", err)
	}
}

func TestValidateStableExecutableRejectsMissingPath(t *testing.T) {
	t.Parallel()

	err := ValidateStableExecutable(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("ValidateStableExecutable returned nil error, want failure")
	}
}

func TestValidateStableExecutableRejectsDirectory(t *testing.T) {
	t.Parallel()

	err := ValidateStableExecutable(t.TempDir())
	if err == nil {
		t.Fatal("ValidateStableExecutable returned nil error, want failure")
	}
}

func TestValidateStableExecutableRejectsNonExecutableFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(path, []byte("not executable\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	err := ValidateStableExecutable(path)
	if err == nil {
		t.Fatal("ValidateStableExecutable returned nil error, want failure")
	}
}

func TestValidateStableExecutableRejectsWritableParent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	parent := filepath.Join(dir, "writable-parent")
	if err := os.Mkdir(parent, 0o777); err != nil { //nolint:gosec // executable trust tests need a writable directory fixture.
		t.Fatalf("mkdir parent: %v", err)
	}
	executable := filepath.Join(parent, "tool")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o555); err != nil { //nolint:gosec // executable trust tests need runnable fixtures.
		t.Fatalf("write executable: %v", err)
	}

	err := ValidateStableExecutable(executable)
	if !errors.Is(err, ErrMutablePath) {
		t.Fatalf("ValidateStableExecutable error = %v, want ErrMutablePath", err)
	}
}
