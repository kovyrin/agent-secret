package helperidentity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
)

func TestForExecutableReturnsCurrentBuildMetadata(t *testing.T) {
	t.Parallel()

	executable := filepath.Join(t.TempDir(), "agent-secretd")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: helper identity test needs an executable fixture.
		t.Fatalf("write executable: %v", err)
	}

	hello := ForExecutable(executable, 1234)
	if hello.Protocol != protocol.ProtocolVersion ||
		hello.AppVersion != buildinfo.Version ||
		hello.BuildID != buildinfo.Revision ||
		hello.PID != 1234 ||
		hello.Executable != pathresolve.BestEffort(executable) {
		t.Fatalf("hello = %+v", hello)
	}
	if hello.BundleID != "" {
		t.Fatalf("direct executable bundle id = %q, want empty", hello.BundleID)
	}
}

func TestBundleIDForExecutableReadsContainingAppBundle(t *testing.T) {
	t.Parallel()

	executable := writeHelperIdentityBundle(t, peertrust.DefaultDaemonBundleID)
	if got := BundleIDForExecutable(executable); got != peertrust.DefaultDaemonBundleID {
		t.Fatalf("BundleIDForExecutable = %q, want %q", got, peertrust.DefaultDaemonBundleID)
	}
	if got := ForExecutable(executable, 5678).BundleID; got != peertrust.DefaultDaemonBundleID {
		t.Fatalf("ForExecutable bundle id = %q, want %q", got, peertrust.DefaultDaemonBundleID)
	}
}

func TestBundleIDForExecutableIgnoresMalformedBundles(t *testing.T) {
	t.Parallel()

	executable := writeHelperIdentityBundle(t, "")
	if got := BundleIDForExecutable(executable); got != "" {
		t.Fatalf("BundleIDForExecutable malformed bundle = %q, want empty", got)
	}
}

func writeHelperIdentityBundle(t *testing.T, bundleID string) string {
	t.Helper()

	bundlePath := filepath.Join(t.TempDir(), "AgentSecretDaemon.app")
	macOSPath := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSPath, 0o750); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	executable := filepath.Join(macOSPath, "Agent Secret")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: helper identity test needs an executable fixture.
		t.Fatalf("write executable: %v", err)
	}
	plist := `<plist><dict><key>CFBundleExecutable</key><string>Agent Secret</string>`
	if bundleID != "" {
		plist += `<key>CFBundleIdentifier</key><string>` + bundleID + `</string>`
	}
	plist += `</dict></plist>`
	if err := os.WriteFile(filepath.Join(bundlePath, "Contents", "Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}
	return executable
}
