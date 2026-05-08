package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kovyrin/agent-secret/internal/install"
)

func (a App) runInstallCLI(command Command) int {
	installCLI := a.InstallCLI
	if installCLI == nil {
		installCLI = install.InstallCLI
	}
	result, err := installCLI(command.InstallCLIOptions)
	if err != nil {
		a.stderrf("agent-secret: install-cli: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secret command installed: %s -> %s\n", result.LinkPath, result.TargetPath)
	a.warnIfCommandDirMissingFromPath(filepath.Dir(result.LinkPath))
	return 0
}

func (a App) runSkillInstall(command Command) int {
	installSkill := a.InstallSkill
	if installSkill == nil {
		installSkill = install.InstallSkill
	}
	result, err := installSkill(command.InstallSkillOptions)
	if err != nil {
		a.stderrf("agent-secret: skill-install: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secret skill installed: %s -> %s\n", result.LinkPath, result.TargetPath)
	return 0
}

func (a App) stdoutf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stdout, format, args...)
}

func (a App) stdoutln(args ...any) {
	_, _ = fmt.Fprintln(a.Stdout, args...)
}

func (a App) stderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stderr, format, args...)
}

func (a App) warnIfCommandDirMissingFromPath(binDir string) {
	if pathContainsDir(os.Getenv("PATH"), binDir) {
		return
	}
	a.stdoutf(
		"\n%s is not on PATH, so `agent-secret` may not work by command name in Terminal.\n"+
			"For zsh, run this one-liner:\n\n"+
			"  %s\n",
		displayHomePath(binDir),
		zshPathSetupCommand(binDir),
	)
}

func pathContainsDir(pathValue string, dir string) bool {
	if pathValue == "" || dir == "" {
		return false
	}
	want := filepath.Clean(dir)
	for _, entry := range filepath.SplitList(pathValue) {
		if entry != "" && filepath.Clean(entry) == want {
			return true
		}
	}
	return false
}

func displayHomePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if suffix, ok := strings.CutPrefix(path, prefix); ok {
		return "~/" + suffix
	}
	return path
}

func shellPathPrefix(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == home {
		return "$HOME"
	}
	prefix := home + string(os.PathSeparator)
	if suffix, ok := strings.CutPrefix(path, prefix); ok {
		return "$HOME/" + suffix
	}
	return path
}

func zshPathSetupCommand(binDir string) string {
	exportLine := fmt.Sprintf("export PATH=\"%s:$PATH\"", shellPathPrefix(binDir))
	quotedLine := shellSingleQuote(exportLine)
	return fmt.Sprintf(
		"grep -qxF %s \"$HOME/.zprofile\" 2>/dev/null || printf '\\n%%s\\n' %s >> \"$HOME/.zprofile\"; exec zsh -l",
		quotedLine,
		quotedLine,
	)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
