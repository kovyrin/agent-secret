package daemon

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedDaemon = errors.New("untrusted daemon peer")

type DaemonPeerValidator interface {
	ValidateDaemonPeer(info peercred.Info) error
}

type TrustedDaemonValidator struct {
	set trustedExecutableSet
}

func NewTrustedDaemonValidator(paths []string) TrustedDaemonValidator {
	return newTrustedDaemonValidator(paths, defaultExpectedTeamID())
}

func newTrustedDaemonValidator(paths []string, expectedTeamID string) TrustedDaemonValidator {
	return TrustedDaemonValidator{
		set: newTrustedExecutableSet(paths, expectedTeamID, ErrUntrustedDaemon),
	}
}

func DefaultTrustedDaemonPaths() []string {
	path, err := defaultDaemonPath()
	if err != nil {
		return nil
	}
	return trustedDaemonPathsForPath(path)
}

func trustedDaemonPathsForPath(path string) []string {
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
	executableName, err := plistString(infoPath, "CFBundleExecutable")
	if err != nil {
		return "", err
	}
	return filepath.Join(bundlePath, "Contents", "MacOS", executableName), nil
}

func (v TrustedDaemonValidator) ValidateDaemonPeer(info peercred.Info) error {
	return v.set.validatePeer(info)
}
