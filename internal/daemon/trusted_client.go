package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrUntrustedClient = errors.New("untrusted daemon client")

type ExecPeerValidator interface {
	ValidateExecPeer(info peercred.Info) error
}

type TrustedExecutableValidator struct {
	paths []string
}

func NewTrustedExecutableValidator(paths []string) TrustedExecutableValidator {
	seen := make(map[string]struct{}, len(paths))
	normalized := make([]string, 0, len(paths))
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
		normalized = append(normalized, path)
	}
	slices.Sort(normalized)
	return TrustedExecutableValidator{paths: normalized}
}

func DefaultTrustedClientPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	dir := filepath.Dir(exe)
	paths := []string{filepath.Join(dir, "agent-secret")}
	if filepath.Base(exe) == "agent-secret" {
		paths = append(paths, exe)
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".local", "bin", "agent-secret"))
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

func (v TrustedExecutableValidator) ValidateExecPeer(info peercred.Info) error {
	if info.ExecutablePath == "" {
		return fmt.Errorf("%w: peer executable path is unavailable", ErrUntrustedClient)
	}
	if len(v.paths) == 0 {
		return fmt.Errorf("%w: no trusted client executables configured", ErrUntrustedClient)
	}
	got := comparablePath(info.ExecutablePath)
	if _, ok := slices.BinarySearch(v.paths, got); ok {
		return nil
	}
	return fmt.Errorf("%w: executable %q is not trusted", ErrUntrustedClient, got)
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
