package peertrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedDaemon = errors.New("untrusted daemon peer")

const DefaultDaemonBundleID = "com.kovyrin.agent-secret.daemon"

type DaemonPeerValidator interface {
	ValidateDaemonPeer(info peercred.Info) error
}

type DaemonValidator struct {
	set executableSet
}

type DaemonProductValidator struct {
	current         DaemonValidator
	expectedTeamID  string
	verifier        trust.CodeSignatureVerifier
	verifySignature bool
}

type DaemonRepairValidator struct{}

func NewDaemonValidator(paths []string) DaemonValidator {
	return newDaemonValidator(paths, trust.DefaultExpectedTeamID())
}

func newDaemonValidator(paths []string, expectedTeamID string) DaemonValidator {
	return DaemonValidator{
		set: newExecutableSet(paths, expectedTeamID, ErrUntrustedDaemon),
	}
}

func NewDaemonProductValidator(paths []string) DaemonProductValidator {
	return newDaemonProductValidatorWithVerifier(
		paths,
		trust.DefaultExpectedTeamID(),
		trust.CodesignSignatureVerifier{},
		runtime.GOOS == "darwin",
	)
}

func newDaemonProductValidatorWithVerifier(
	paths []string,
	expectedTeamID string,
	verifier trust.CodeSignatureVerifier,
	verifySignature bool,
) DaemonProductValidator {
	return DaemonProductValidator{
		current:         newDaemonValidator(paths, expectedTeamID),
		expectedTeamID:  strings.TrimSpace(expectedTeamID),
		verifier:        verifier,
		verifySignature: verifySignature,
	}
}

func DaemonPathsForPath(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if filepath.Ext(path) != ".app" {
		return []string{path}, nil
	}
	executable, err := bundleExecutablePath(path)
	if err != nil {
		return nil, err
	}
	return []string{executable}, nil
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

func (v DaemonProductValidator) ValidateDaemonPeer(info peercred.Info) error {
	if err := v.current.ValidateDaemonPeer(info); err == nil {
		return nil
	}
	if err := validateDaemonPeerOwner(info); err != nil {
		return err
	}
	if !v.verifySignature {
		return fmt.Errorf("%w: executable %q is not a current trusted helper", ErrUntrustedDaemon, info.ExecutablePath)
	}
	requiredTeamID, enforceTeamID, err := trust.ExpectedTeamIDForSignatureValidation(v.expectedTeamID, ErrUntrustedDaemon)
	if err != nil {
		return err
	}
	if !enforceTeamID {
		return fmt.Errorf("%w: broad helper repair trust requires a release Team ID", ErrUntrustedDaemon)
	}
	bundlePath, err := daemonProductBundlePath(info.ExecutablePath)
	if err != nil {
		return err
	}
	if err := trust.ValidatePeerSignature(info, bundlePath, requiredTeamID, v.verifier, ErrUntrustedDaemon); err != nil {
		return err
	}
	return nil
}

func NewDaemonRepairValidator() DaemonRepairValidator {
	return DaemonRepairValidator{}
}

func (DaemonRepairValidator) ValidateDaemonPeer(info peercred.Info) error {
	if err := validateDaemonPeerOwner(info); err != nil {
		return err
	}
	_, err := daemonProductBundlePath(info.ExecutablePath)
	return err
}

func validateDaemonPeerOwner(info peercred.Info) error {
	if info.UID != os.Getuid() {
		return fmt.Errorf("%w: daemon uid %d != %d", ErrUntrustedDaemon, info.UID, os.Getuid())
	}
	if info.GID != os.Getgid() {
		return fmt.Errorf("%w: daemon gid %d != %d", ErrUntrustedDaemon, info.GID, os.Getgid())
	}
	return nil
}

func daemonProductBundlePath(executablePath string) (string, error) {
	executable, err := pathresolve.Strict(executablePath)
	if err != nil {
		return "", fmt.Errorf("%w: normalize daemon executable %q: %w", ErrUntrustedDaemon, executablePath, err)
	}
	bundlePath, ok := containingAppBundlePath(executable)
	if !ok || filepath.Base(bundlePath) != "AgentSecretDaemon.app" {
		return "", fmt.Errorf("%w: executable %q is not an Agent Secret daemon helper app", ErrUntrustedDaemon, executable)
	}
	bundleID, err := trust.PlistString(filepath.Join(bundlePath, "Contents", "Info.plist"), "CFBundleIdentifier", ErrUntrustedDaemon)
	if err != nil {
		return "", err
	}
	if bundleID != DefaultDaemonBundleID {
		return "", fmt.Errorf("%w: daemon bundle id %q != %q", ErrUntrustedDaemon, bundleID, DefaultDaemonBundleID)
	}
	return bundlePath, nil
}
