package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootstrapUpdaterFromBundledCLI(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	host := filepath.Join(root, "Agent Secret.app")
	executable := filepath.Join(host, "Contents", "Resources", "bin", "agent-secret")
	app := filepath.Join(host, "Contents", "MacOS", "Agent Secret")
	marker := filepath.Join(root, "bootstrapped")
	if err := os.MkdirAll(filepath.Dir(app), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, []byte("#!/bin/sh\n[ \"$1\" = --restore-background-updater ] || exit 64\nprintf ready > '"+marker+"'\n"), 0o700); err != nil { //nolint:gosec // G306: bootstrap tests require a runnable fixture under t.TempDir.
		t.Fatal(err)
	}
	if err := bootstrapUpdater(context.Background(), executable); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "ready" { //nolint:gosec // G304: marker is a synthetic fixture under t.TempDir.
		t.Fatalf("updater bootstrap did not run: got %q, error %v", got, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "agent-secret")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapUpdater(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("linked CLI did not bootstrap updater: %v", err)
	}
}

func TestBootstrapUpdaterSkipsStandaloneCLI(t *testing.T) {
	t.Parallel()
	if err := bootstrapUpdater(context.Background(), filepath.Join(t.TempDir(), "agent-secret")); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapUpdaterReportsRegistrationFailure(t *testing.T) {
	t.Parallel()
	host := filepath.Join(t.TempDir(), "Agent Secret.app")
	app := filepath.Join(host, "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(app), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, []byte("#!/bin/sh\nexit 64\n"), 0o700); err != nil { //nolint:gosec // G306: bootstrap tests require a runnable fixture under t.TempDir.
		t.Fatal(err)
	}
	if err := bootstrapUpdater(context.Background(), filepath.Join(host, "Contents", "Resources", "bin", "agent-secret")); err == nil {
		t.Fatal("expected registration error")
	}
}

func TestBootstrapUpdaterBoundsRegistrationTime(t *testing.T) {
	t.Parallel()
	host := filepath.Join(t.TempDir(), "Agent Secret.app")
	app := filepath.Join(host, "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(app), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0o700); err != nil { //nolint:gosec // G306: bootstrap tests require a runnable fixture under t.TempDir.
		t.Fatal(err)
	}
	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		done <- bootstrapUpdater(ctx, filepath.Join(host, "Contents", "Resources", "bin", "agent-secret"))
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bootstrap error = %v, want bounded deadline", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("updater registration blocked the CLI beyond its five-second budget")
	}
}
