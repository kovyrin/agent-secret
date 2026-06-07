package bwsm

import (
	"os"
	"path/filepath"
	"slices"
)

const (
	agentSecretAppBundleName    = "Agent Secret.app"
	agentSecretAppExecutable    = "Agent Secret"
	agentSecretDaemonBundleName = "AgentSecretDaemon.app"
	agentSecretCLIBinaryName    = "agent-secret"
	agentSecretDaemonBinaryName = "agent-secretd"
)

func trustedKeychainApplicationPaths() []string {
	executable, err := os.Executable()
	if err != nil {
		return nil
	}
	return trustedKeychainApplicationPathsForExecutable(executable)
}

func trustedKeychainApplicationPathsForExecutable(executable string) []string {
	var paths []string
	appendPath := func(path string) {
		path = filepath.Clean(path)
		if path == "." || !filepath.IsAbs(path) || slices.Contains(paths, path) {
			return
		}
		if _, err := os.Stat(path); err != nil {
			return
		}
		paths = append(paths, path)
	}
	appendRelatedPaths := func(path string) {
		appendPath(path)
		appendBundleTrustedPaths(path, appendPath)
		appendSiblingDaemonPaths(path, appendPath)
	}

	appendRelatedPaths(executable)
	resolved, err := filepath.EvalSymlinks(executable)
	if err == nil && resolved != executable {
		appendRelatedPaths(resolved)
	}
	return paths
}

func appendBundleTrustedPaths(path string, appendPath func(string)) {
	appRoot, ok := agentSecretAppRoot(path)
	if !ok {
		return
	}
	daemonApp := filepath.Join(
		appRoot,
		"Contents",
		"Library",
		"Helpers",
		agentSecretDaemonBundleName,
	)
	appendPath(filepath.Join(appRoot, "Contents", "Resources", "bin", agentSecretCLIBinaryName))
	appendPath(daemonApp)
	appendPath(filepath.Join(daemonApp, "Contents", "MacOS", agentSecretAppExecutable))
}

func appendSiblingDaemonPaths(path string, appendPath func(string)) {
	dir := filepath.Dir(path)
	switch filepath.Base(path) {
	case agentSecretCLIBinaryName:
		appendPath(filepath.Join(dir, agentSecretDaemonBinaryName))
	case agentSecretDaemonBinaryName:
		appendPath(filepath.Join(dir, agentSecretCLIBinaryName))
	}
}

func agentSecretAppRoot(path string) (string, bool) {
	for current := filepath.Clean(path); current != "." && current != string(filepath.Separator); current = filepath.Dir(current) {
		if filepath.Base(current) == agentSecretAppBundleName {
			return current, true
		}
	}
	return "", false
}
