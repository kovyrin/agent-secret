package peertrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedDaemon = errors.New("untrusted daemon peer")

type DaemonPeerValidator interface {
	ValidateDaemonPeer(info peercred.Info) error
}

type DaemonValidator struct {
	set executableSet
}

func NewDaemonValidator(paths []string) DaemonValidator {
	return newDaemonValidator(paths, trust.DefaultExpectedTeamID())
}

func newDaemonValidator(paths []string, expectedTeamID string) DaemonValidator {
	return DaemonValidator{
		set: newExecutableSet(paths, expectedTeamID, ErrUntrustedDaemon),
	}
}

func DaemonPathsForPath(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if filepath.Ext(path) != ".app" {
		return []string{path}
	}
	executable, err := bundleExecutablePath(path)
	if err != nil {
		return nil
	}
	return []string{executable}
}

func bundleExecutablePath(bundlePath string) (string, error) {
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	executableName, err := trust.PlistString(infoPath, "CFBundleExecutable", ErrUntrustedDaemon)
	if err != nil {
		return "", err
	}
	return filepath.Join(bundlePath, "Contents", "MacOS", executableName), nil
}

func (v DaemonValidator) ValidateDaemonPeer(info peercred.Info) error {
	if info.UID != os.Getuid() {
		return fmt.Errorf("%w: daemon uid %d != %d", ErrUntrustedDaemon, info.UID, os.Getuid())
	}
	if info.GID != os.Getgid() {
		return fmt.Errorf("%w: daemon gid %d != %d", ErrUntrustedDaemon, info.GID, os.Getgid())
	}
	return v.set.validatePeer(info)
}
