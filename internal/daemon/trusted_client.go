package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedClient = errors.New("untrusted daemon client")

type ExecPeerValidator interface {
	ValidateExecPeer(info peercred.Info) error
}

type TrustedExecutableValidator struct {
	set trustedExecutableSet
}

type trustedExecutableSet struct {
	entries           []trustedExecutable
	expectedTeamID    string
	err               error
	signatureVerifier codeSignatureVerifier
	verifySignature   bool
}

type trustedExecutable struct {
	path       string
	fileInfo   os.FileInfo
	bundlePath string
}

func NewTrustedExecutableValidator(paths []string) TrustedExecutableValidator {
	return newTrustedExecutableValidator(paths, defaultExpectedTeamID())
}

func newTrustedExecutableValidator(paths []string, expectedTeamID string) TrustedExecutableValidator {
	return TrustedExecutableValidator{
		set: newTrustedExecutableSet(paths, expectedTeamID, ErrUntrustedClient),
	}
}

func newTrustedExecutableSet(paths []string, expectedTeamID string, err error) trustedExecutableSet {
	return newTrustedExecutableSetWithVerifier(
		paths,
		expectedTeamID,
		err,
		codesignSignatureVerifier{},
		runtime.GOOS == "darwin",
	)
}

func newTrustedExecutableSetWithVerifier(
	paths []string,
	expectedTeamID string,
	err error,
	verifier codeSignatureVerifier,
	verifySignature bool,
) trustedExecutableSet {
	seen := make(map[string]struct{}, len(paths))
	entries := make([]trustedExecutable, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		path = comparablePath(path)
		if _, ok := seen[path]; ok {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		seen[path] = struct{}{}
		entry := trustedExecutable{
			path:     path,
			fileInfo: info,
		}
		if bundlePath, ok := trustedClientBundlePath(path); ok {
			entry.bundlePath = bundlePath
		}
		entries = append(entries, entry)
	}
	return trustedExecutableSet{
		entries:           entries,
		expectedTeamID:    strings.TrimSpace(expectedTeamID),
		err:               err,
		signatureVerifier: verifier,
		verifySignature:   verifySignature,
	}
}

func DefaultTrustedClientPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return trustedClientPathsForExecutable(exe)
}

func trustedClientPathsForExecutable(exe string) []string {
	dir := filepath.Dir(exe)
	paths := []string{filepath.Join(dir, "agent-secret")}
	if filepath.Base(exe) == "agent-secret" {
		paths = append(paths, exe)
	}
	if bundledCLI, ok := bundledCLIPathForDaemonExecutable(exe); ok {
		paths = append(paths, bundledCLI)
	}
	return paths
}

func CurrentExecutableTrustedClientPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return []string{exe}
}

func bundledCLIPathForDaemonExecutable(exe string) (string, bool) {
	bundlePath, ok := containingAppBundlePath(exe)
	if !ok || filepath.Base(bundlePath) != "AgentSecretDaemon.app" {
		return "", false
	}
	hostApp := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(bundlePath))))
	if filepath.Ext(hostApp) != ".app" {
		return "", false
	}
	return filepath.Join(hostApp, "Contents", "Resources", "bin", "agent-secret"), true
}

func trustedClientBundlePath(path string) (string, bool) {
	if filepath.Base(path) != "agent-secret" {
		return "", false
	}
	binDir := filepath.Dir(path)
	if filepath.Base(binDir) != "bin" {
		return "", false
	}
	resourcesDir := filepath.Dir(binDir)
	if filepath.Base(resourcesDir) != "Resources" {
		return "", false
	}
	contentsDir := filepath.Dir(resourcesDir)
	if filepath.Base(contentsDir) != "Contents" {
		return "", false
	}
	appPath := filepath.Dir(contentsDir)
	if filepath.Ext(appPath) != ".app" {
		return "", false
	}
	return filepath.Clean(appPath), true
}

func containingAppBundlePath(path string) (string, bool) {
	dir := filepath.Dir(path)
	for {
		if filepath.Ext(dir) == ".app" {
			return filepath.Clean(dir), true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func (v TrustedExecutableValidator) ValidateExecPeer(info peercred.Info) error {
	return v.set.validatePeer(info)
}

func (v trustedExecutableSet) validatePeer(info peercred.Info) error {
	if v.err == nil {
		v.err = ErrUntrustedClient
	}
	if info.ExecutablePath == "" {
		return fmt.Errorf("%w: peer executable path is unavailable", v.err)
	}
	if len(v.entries) == 0 {
		return fmt.Errorf("%w: no trusted executables configured", v.err)
	}
	got := comparablePath(info.ExecutablePath)
	for _, entry := range v.entries {
		if entry.path != got {
			continue
		}
		if err := entry.validatePeer(info, got, v.expectedTeamID, v.signatureVerifier, v.verifySignature, v.err); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: executable %q is not trusted", v.err, got)
}

func (e trustedExecutable) validatePeer(
	info peercred.Info,
	path string,
	expectedTeamID string,
	verifier codeSignatureVerifier,
	verifySignature bool,
	errKind error,
) error {
	if errKind == nil {
		errKind = ErrUntrustedClient
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: stat trusted executable %q: %w", errKind, path, err)
	}
	if !os.SameFile(fileInfo, e.fileInfo) {
		return fmt.Errorf("%w: executable %q changed since trust snapshot", errKind, path)
	}
	if e.bundlePath != "" {
		currentBundlePath, ok := trustedClientBundlePath(path)
		if !ok || currentBundlePath != e.bundlePath {
			return fmt.Errorf("%w: executable %q is outside expected app bundle %q", errKind, path, e.bundlePath)
		}
	}
	if !verifySignature || (expectedTeamID == "" && !e.isBundledPath(path)) {
		return nil
	}
	requiredTeamID, enforceTeamID, err := expectedTeamIDForSignatureValidation(expectedTeamID, errKind)
	if err != nil {
		return err
	}
	if enforceTeamID {
		return validatePeerSignature(info, path, requiredTeamID, verifier, errKind)
	}
	return nil
}

func (e trustedExecutable) isBundledPath(path string) bool {
	if e.bundlePath != "" {
		return true
	}
	_, ok := containingAppBundlePath(path)
	return ok
}

func validatePeerSignature(
	info peercred.Info,
	path string,
	expectedTeamID string,
	verifier codeSignatureVerifier,
	errKind error,
) error {
	if verifier == nil {
		verifier = codesignSignatureVerifier{}
	}
	if info.PID <= 0 {
		return fmt.Errorf("%w: peer pid is unavailable for signature validation", errKind)
	}
	teamID, err := verifier.VerifyPath(path)
	if err != nil {
		return fmt.Errorf("%w: verify trusted executable signature: %w", errKind, err)
	}
	if teamID != expectedTeamID {
		return fmt.Errorf("%w: trusted executable team id %q != %q", errKind, teamID, expectedTeamID)
	}
	teamID, err = verifier.VerifyProcess(info.PID)
	if err != nil {
		return fmt.Errorf("%w: verify peer process signature: %w", errKind, err)
	}
	if teamID != expectedTeamID {
		return fmt.Errorf("%w: peer process team id %q != %q", errKind, teamID, expectedTeamID)
	}
	return nil
}

func comparablePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}
