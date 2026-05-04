package appbundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteApproverBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	executable := WriteApproverBundle(t, dir, "com.example.approver", "Example Approver")
	bundle := filepath.Join(dir, "AgentSecretApprover.app")

	if executable != filepath.Join(bundle, "Contents", "MacOS", "Example Approver") {
		t.Fatalf("executable path = %q, want path inside bundle", executable)
	}
	assertFileMode(t, filepath.Join(bundle, "Contents", "MacOS"), 0o750)
	assertFileMode(t, executable, 0o755)
	assertFileMode(t, filepath.Join(bundle, "Contents", "Info.plist"), 0o600)

	script, err := os.ReadFile(executable) //nolint:gosec // G304: test reads the executable fixture path returned from WriteApproverBundle under t.TempDir.
	if err != nil {
		t.Fatalf("read executable fixture: %v", err)
	}
	if string(script) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("executable fixture = %q, want shell stub", string(script))
	}

	plist, err := os.ReadFile(filepath.Join(bundle, "Contents", "Info.plist")) //nolint:gosec // G304: test reads a fixture path under t.TempDir.
	if err != nil {
		t.Fatalf("read Info.plist fixture: %v", err)
	}
	plistText := string(plist)
	for _, want := range []string{
		"<key>CFBundleIdentifier</key>",
		"<string>com.example.approver</string>",
		"<key>CFBundleExecutable</key>",
		"<string>Example Approver</string>",
	} {
		if !strings.Contains(plistText, want) {
			t.Fatalf("Info.plist missing %q in:\n%s", want, plistText)
		}
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s = %v, want %v", path, got, want)
	}
}
