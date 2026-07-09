package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kovyrin/agent-secret/internal/install"
)

type installOutput struct {
	SchemaVersion string       `json:"schema_version"`
	Installed     bool         `json:"installed"`
	LinkPath      string       `json:"link_path"`
	TargetPath    string       `json:"target_path"`
	PathWarning   *pathWarning `json:"path_warning,omitempty"`
}

type pathWarning struct {
	Directory  string `json:"directory"`
	Command    string `json:"command"`
	ShadowedBy string `json:"shadowed_by,omitempty"`
}

func (a App) runInstallCLI(ctx context.Context, command Command) int {
	installCLI := a.InstallCLI
	if installCLI == nil {
		installCLI = install.InstallCLI
	}
	result, err := installCLI(command.InstallCLIOptions)
	if err != nil {
		if command.OutputJSON {
			return a.writeJSONError("install-cli", err)
		}
		a.stderrf("agent-secret: install-cli: %v\n", err)
		return 1
	}
	if err := a.tryRepairBackgroundHelperAfterInstall(ctx); err != nil {
		if command.OutputJSON {
			return a.writeJSONError("install-cli", err)
		}
		a.stderrf("agent-secret: install-cli: %v\n", err)
		return 1
	}
	if command.OutputJSON {
		output := installOutput{
			SchemaVersion: "1",
			Installed:     true,
			LinkPath:      result.LinkPath,
			TargetPath:    result.TargetPath,
		}
		if warning := commandPathWarning(os.Getenv("PATH"), result.LinkPath); warning != nil {
			output.PathWarning = warning
		}
		if err := a.writeJSON(output); err != nil {
			a.stderrf("agent-secret: write install-cli json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutf("agent-secret command installed: %s -> %s\n", result.LinkPath, result.TargetPath)
	a.warnIfCommandDirMissingFromPath(filepath.Dir(result.LinkPath))
	return 0
}

func (a App) tryRepairBackgroundHelperAfterInstall(ctx context.Context) error {
	manager, err := a.daemonManager()
	if err != nil {
		return fmt.Errorf("activate Agent Secret local service: %w", err)
	}
	if err := a.ensureBackgroundHelper(ctx, manager); err != nil {
		return errors.New(backgroundHelperError(err))
	}
	return nil
}

func (a App) runSkillInstall(command Command) int {
	installSkill := a.InstallSkill
	if installSkill == nil {
		installSkill = install.InstallSkill
	}
	result, err := installSkill(command.InstallSkillOptions)
	if err != nil {
		if command.OutputJSON {
			return a.writeJSONError("skill-install", err)
		}
		a.stderrf("agent-secret: skill-install: %v\n", err)
		return 1
	}
	if command.OutputJSON {
		if err := a.writeJSON(installOutput{
			SchemaVersion: "1",
			Installed:     true,
			LinkPath:      result.LinkPath,
			TargetPath:    result.TargetPath,
		}); err != nil {
			a.stderrf("agent-secret: write skill-install json: %v\n", err)
			return 1
		}
		return 0
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
	warning := commandPathWarning(os.Getenv("PATH"), filepath.Join(binDir, install.CommandName))
	if warning == nil {
		return
	}
	if warning.ShadowedBy != "" {
		a.stdoutf(
			"\nAn earlier PATH entry contains agent-secret, so Terminal may run %s instead of %s.\n"+
				"Remove the stale command or put %s first on PATH.\n"+
				"For zsh, run this one-liner:\n\n"+
				"  %s\n",
			warning.ShadowedBy,
			filepath.Join(warning.Directory, install.CommandName),
			warning.Directory,
			warning.Command,
		)
		return
	}
	a.stdoutf(
		"\n%s is not on PATH, so `agent-secret` may not work by command name in Terminal.\n"+
			"For zsh, run this one-liner:\n\n"+
			"  %s\n",
		warning.Directory,
		warning.Command,
	)
}

func commandPathWarning(pathValue string, linkPath string) *pathWarning {
	binDir := filepath.Dir(linkPath)
	command := zshPathSetupCommand(binDir)
	warning := &pathWarning{Directory: displayHomePath(binDir), Command: command}
	if pathValue == "" || binDir == "" {
		return warning
	}
	want := filepath.Clean(binDir)
	for _, entry := range filepath.SplitList(pathValue) {
		if entry == "" {
			continue
		}
		cleanEntry := filepath.Clean(entry)
		if cleanEntry == want {
			return nil
		}
		candidate := filepath.Join(entry, install.CommandName)
		if executableFileExists(candidate) {
			warning.ShadowedBy = candidate
			return warning
		}
	}
	return warning
}

func executableFileExists(path string) bool {
	info, err := os.Stat(path) // #nosec G703 -- probing PATH-derived candidates only checks executable existence; it does not read or execute the path.
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
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

func zshPathSetupCommand(binDir string) string {
	exportLine := fmt.Sprintf("export PATH=%s:\"$PATH\"", shellSingleQuote(binDir))
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
