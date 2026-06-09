package helperidentity

import (
	"os"
	"path/filepath"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
)

func Current() protocol.HelperHelloPayload {
	executable, _ := os.Executable()
	return ForExecutable(executable, os.Getpid())
}

func ForExecutable(executable string, pid int) protocol.HelperHelloPayload {
	executable = pathresolve.BestEffort(executable)
	return protocol.HelperHelloPayload{
		Protocol:   protocol.ProtocolVersion,
		AppVersion: buildinfo.Version,
		BuildID:    buildinfo.Revision,
		PID:        pid,
		Executable: executable,
		TeamID:     trust.DefaultExpectedTeamID(),
		BundleID:   BundleIDForExecutable(executable),
	}
}

func BundleIDForExecutable(executable string) string {
	bundlePath, ok := containingAppBundlePath(executable)
	if !ok {
		return ""
	}
	bundleID, err := trust.PlistString(
		filepath.Join(bundlePath, "Contents", "Info.plist"),
		"CFBundleIdentifier",
		peertrust.ErrUntrustedDaemon,
	)
	if err != nil {
		return ""
	}
	return bundleID
}

func containingAppBundlePath(path string) (string, bool) {
	path = pathresolve.BestEffort(path)
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		if filepath.Ext(current) == ".app" {
			return filepath.Clean(current), true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
	}
}
