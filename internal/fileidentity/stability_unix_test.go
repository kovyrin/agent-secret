//go:build unix

package fileidentity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMutableByCurrentUserDetectsOwnedExecutable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "exit 0\n")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat executable: %v", err)
	}
	if !mutableByCurrentUser(path, info, false) {
		t.Fatal("mutableByCurrentUser = false, want true for current-user-owned file")
	}
}
