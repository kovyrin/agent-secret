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
	entries        []trustedExecutable
	expectedTeamID string
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
	return TrustedExecutableValidator{
		entries:        entries,
		expectedTeamID: strings.TrimSpace(expectedTeamID),
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
	if info.ExecutablePath == "" {
		return fmt.Errorf("%w: peer executable path is unavailable", ErrUntrustedClient)
	}
	if len(v.entries) == 0 {
		return fmt.Errorf("%w: no trusted client executables configured", ErrUntrustedClient)
	}
	got := comparablePath(info.ExecutablePath)
	for _, entry := range v.entries {
		if entry.path != got {
			continue
		}
		if err := entry.validate(got, v.expectedTeamID); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: executable %q is not trusted", ErrUntrustedClient, got)
}

func (e trustedExecutable) validate(path string, expectedTeamID string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: stat trusted executable %q: %w", ErrUntrustedClient, path, err)
	}
	if !os.SameFile(info, e.fileInfo) {
		return fmt.Errorf("%w: executable %q changed since daemon startup", ErrUntrustedClient, path)
	}
	if e.bundlePath != "" {
		currentBundlePath, ok := trustedClientBundlePath(path)
		if !ok || currentBundlePath != e.bundlePath {
			return fmt.Errorf("%w: executable %q is outside expected app bundle %q", ErrUntrustedClient, path, e.bundlePath)
		}
	}
	if expectedTeamID != "" && runtime.GOOS == "darwin" {
		teamID, err := verifyCodeSignature(path)
		if err != nil {
			return fmt.Errorf("%w: verify code signature: %w", ErrUntrustedClient, err)
		}
		if teamID != expectedTeamID {
			return fmt.Errorf("%w: team id %q != %q", ErrUntrustedClient, teamID, expectedTeamID)
		}
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
