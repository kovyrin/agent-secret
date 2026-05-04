package appbundle

import (
	"os"
	"path/filepath"
	"testing"
)

func WriteApproverBundle(t *testing.T, dir string, bundleID string, executableName string) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "AgentSecretApprover.app")
	macOSPath := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSPath, 0o750); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	executablePath := filepath.Join(macOSPath, executableName)
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: bundle identity tests need runnable app executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>` + bundleID + `</string>
  <key>CFBundleExecutable</key>
  <string>` + executableName + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(bundlePath, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}
	return executablePath
}
