package peertrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedClient = errors.New("untrusted daemon client")

type ExecValidator interface {
	ValidateExecPeer(info peercred.Info) error
}

type ExecutableValidator struct {
	set executableSet
}

type executableSet struct {
	entries           []executable
	expectedTeamID    string
	err               error
	candidateErr      error
	signatureVerifier trust.CodeSignatureVerifier
	verifySignature   bool
}

type executable struct {
	path       string
	fileInfo   os.FileInfo
	bundlePath string
}

func NewExecutableValidator(paths []string) ExecutableValidator {
	return newExecutableValidator(paths, trust.DefaultExpectedTeamID())
}

func newExecutableValidator(paths []string, expectedTeamID string) ExecutableValidator {
	return ExecutableValidator{
		set: newExecutableSet(paths, expectedTeamID, ErrUntrustedClient),
	}
}

func newExecutableSet(paths []string, expectedTeamID string, err error) executableSet {
	return newExecutableSetWithVerifier(
		paths,
		expectedTeamID,
		err,
		trust.CodesignSignatureVerifier{},
		runtime.GOOS == "darwin",
	)
}

func newExecutableSetWithVerifier(
	paths []string,
	expectedTeamID string,
	err error,
	verifier trust.CodeSignatureVerifier,
	verifySignature bool,
) executableSet {
	seen := make(map[string]struct{}, len(paths))
	entries := make([]executable, 0, len(paths))
	var candidateErrs []error
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		path = comparablePath(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		info, err := os.Stat(path)
		if err != nil {
			candidateErrs = append(candidateErrs, fmt.Errorf("stat trusted executable %q: %w", path, err))
			continue
		}
		if info.IsDir() {
			candidateErrs = append(candidateErrs, fmt.Errorf("trusted executable %q is a directory", path))
			continue
		}
		entry := executable{
			path:     path,
			fileInfo: info,
		}
		if bundlePath, ok := clientBundlePath(path); ok {
			entry.bundlePath = bundlePath
		}
		entries = append(entries, entry)
	}
	return executableSet{
		entries:           entries,
		expectedTeamID:    strings.TrimSpace(expectedTeamID),
		err:               err,
		candidateErr:      errors.Join(candidateErrs...),
		signatureVerifier: verifier,
		verifySignature:   verifySignature,
	}
}

func DefaultClientPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	return clientPathsForExecutable(exe)
}

func clientPathsForExecutable(exe string) []string {
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

func CurrentExecutableClientPaths() []string {
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

func clientBundlePath(path string) (string, bool) {
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

func (v ExecutableValidator) ValidateExecPeer(info peercred.Info) error {
	return v.set.validatePeer(info)
}

func (v executableSet) validatePeer(info peercred.Info) error {
	if v.err == nil {
		v.err = ErrUntrustedClient
	}
	if info.ExecutablePath == "" {
		return fmt.Errorf("%w: peer executable path is unavailable", v.err)
	}
	if len(v.entries) == 0 {
		if v.candidateErr != nil {
			return fmt.Errorf("%w: no trusted executables configured: %w", v.err, v.candidateErr)
		}
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

func (e executable) validatePeer(
	info peercred.Info,
	path string,
	expectedTeamID string,
	verifier trust.CodeSignatureVerifier,
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
		currentBundlePath, ok := clientBundlePath(path)
		if !ok || currentBundlePath != e.bundlePath {
			return fmt.Errorf("%w: executable %q is outside expected app bundle %q", errKind, path, e.bundlePath)
		}
	}
	if !verifySignature || (expectedTeamID == "" && !e.isBundledPath(path)) {
		return nil
	}
	requiredTeamID, enforceTeamID, err := trust.ExpectedTeamIDForSignatureValidation(expectedTeamID, errKind)
	if err != nil {
		return err
	}
	if enforceTeamID {
		return trust.ValidatePeerSignature(info, path, requiredTeamID, verifier, errKind)
	}
	return nil
}

func (e executable) isBundledPath(path string) bool {
	if e.bundlePath != "" {
		return true
	}
	_, ok := containingAppBundlePath(path)
	return ok
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
