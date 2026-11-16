package request

import (
	"fmt"
	"slices"
	"strings"
)

// CodeLoadingEnvironmentNames identifies inherited variables that can cause a
// child or a tool it launches to load code not visible in argv.
func CodeLoadingEnvironmentNames(env []string) []string {
	names := make([]string, 0)
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if ok && isCodeLoadingEnvironmentName(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
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

func validateCodeLoadingEnvironmentNames(names []string) error {
	if len(names) > 128 || !slices.IsSorted(names) {
		return fmt.Errorf("%w: code-loading environment names are not bounded and sorted", ErrInvalidRequest)
	}
	for i, name := range names {
		if !isCodeLoadingEnvironmentName(name) || (i > 0 && names[i-1] == name) {
			return fmt.Errorf("%w: invalid code-loading environment name", ErrInvalidRequest)
		}
	}
	return nil
}
