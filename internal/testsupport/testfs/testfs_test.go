package testfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatModeReturnsPermissionBits(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}

	if got := StatMode(t, path); got != 0o750 {
		t.Fatalf("StatMode = %v, want 0750", got)
	}
}

func TestShortTempDirCreatesTmpDirAndRegistersCleanup(t *testing.T) {
	t.Parallel()

	var dir string
	t.Run("create", func(t *testing.T) {
		dir = ShortTempDir(t, "agent-secret-testfs-")
		if !strings.HasPrefix(dir, "/tmp/agent-secret-testfs-") {
			t.Fatalf("ShortTempDir = %q, want /tmp/agent-secret-testfs-*", dir)
		}
		if got := StatMode(t, dir); got != 0o700 {
			t.Fatalf("ShortTempDir mode = %v, want 0700", got)
		}
	})

	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ShortTempDir cleanup stat error = %v, want os.ErrNotExist", err)
	}
}
