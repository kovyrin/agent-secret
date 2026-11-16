package request

import (
	"fmt"
	"slices"
	"strings"
)

const maxCodeLoadingEnvironmentBytes = 8 * 1024

// CodeLoadingEnvironmentEntries selects inherited variables that can cause a
// child or a tool it launches to load code not visible in argv. Duplicate
// names use the final value, matching os/exec's environment behavior.
func CodeLoadingEnvironmentEntries(env []string) []string {
	entries := make([]string, 0)
	for _, entry := range canonicalEnv(env) {
		name, _, ok := strings.Cut(entry, "=")
		if ok && isCodeLoadingEnvironmentName(name) {
			entries = append(entries, entry)
		}
	}
	slices.Sort(entries)
	return entries
}

func isCodeLoadingEnvironmentName(name string) bool {
	switch name {
	case "BASH_ENV", "ENV", "NODE_OPTIONS", "NODE_PATH", "NPM_CONFIG_SCRIPT_SHELL", "npm_config_script_shell",
		"GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_ASKPASS", "SSH_ASKPASS", "PYTHONSTARTUP", "PYTHONPATH",
		"PYTHONHOME", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "LD_PRELOAD", "LD_LIBRARY_PATH",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH":
		return true
	default:
		return strings.HasPrefix(name, "DYLD_") || strings.HasPrefix(name, "GIT_CONFIG_")
	}
}

func validateCodeLoadingEnvironmentEntries(entries []string) error {
	if len(entries) > 128 || !slices.IsSorted(entries) {
		return fmt.Errorf("%w: code-loading environment entries are not bounded and sorted", ErrInvalidRequest)
	}
	totalBytes := 0
	previousName := ""
	for _, entry := range entries {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || !isCodeLoadingEnvironmentName(name) || name == previousName {
			return fmt.Errorf("%w: invalid code-loading environment entry", ErrInvalidRequest)
		}
		totalBytes += len(entry)
		if totalBytes > maxCodeLoadingEnvironmentBytes {
			return fmt.Errorf("%w: code-loading environment is too large to display; remove or shorten these variables", ErrInvalidRequest)
		}
		previousName = name
	}
	return nil
}
