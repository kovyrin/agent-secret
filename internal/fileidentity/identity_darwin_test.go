//go:build darwin

package fileidentity

import (
	"path/filepath"
	"testing"
)

func TestAddPlatformIdentityDarwinCapturesStatMetadata(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "tool")
	writeExecutable(t, path, "exit 0\n")
	identity, err := Capture(path)
	if err != nil {
		t.Fatalf("Capture returned error: %v", err)
	}
	if identity.Device == 0 {
		t.Fatal("Device = 0, want captured device")
	}
	if identity.Inode == 0 {
		t.Fatal("Inode = 0, want captured inode")
	}
	if identity.ChangeTimeUnixNano == 0 {
		t.Fatal("ChangeTimeUnixNano = 0, want captured change time")
	}
}
