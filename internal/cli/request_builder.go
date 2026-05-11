package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/request"
)

type execRequestBuildOptions struct {
	reason       string
	command      []string
	cwd          string
	env          []string
	secrets      []request.SecretSpec
	ttl          time.Duration
	overrideEnv  bool
	forceRefresh bool
	reuseOnly    bool
}

func buildExecRequest(opts execRequestBuildOptions) (request.ExecRequest, error) {
	if err := request.ValidateReason(opts.reason); err != nil {
		return request.ExecRequest{}, err
	}
	cwd, err := normalizeCWD(opts.cwd)
	if err != nil {
		return request.ExecRequest{}, err
	}

	env := slices.Clone(opts.env)
	command, resolvedExecutable, err := resolveCommand(cwd, env, opts.command)
	if err != nil {
		return request.ExecRequest{}, err
	}
	executableIdentity, err := fileidentity.Capture(resolvedExecutable)
	if err != nil {
		return request.ExecRequest{}, fmt.Errorf("%w: capture executable identity: %w", request.ErrInvalidCommand, err)
	}
	secrets, err := request.ParseSecrets(opts.secrets)
	if err != nil {
		return request.ExecRequest{}, err
	}
	overriddenAliases, err := detectOverrides(env, secrets, opts.overrideEnv)
	if err != nil {
		return request.ExecRequest{}, err
	}

	return request.NewExec(request.ExecOptions{
		Reason:                 opts.reason,
		Command:                command,
		ResolvedExecutable:     resolvedExecutable,
		ExecutableIdentity:     executableIdentity,
		CWD:                    cwd,
		EnvironmentFingerprint: request.EnvironmentFingerprint(env),
		Secrets:                opts.secrets,
		TTL:                    opts.ttl,
		OverrideEnv:            opts.overrideEnv,
		OverriddenAliases:      overriddenAliases,
		ForceRefresh:           opts.forceRefresh,
		ReuseOnly:              opts.reuseOnly,
	})
}

type itemDescribeRequestBuildOptions struct {
	reason             string
	command            []string
	cwd                string
	resolvedExecutable string
	ref                string
	account            string
	ttl                time.Duration
}

func buildItemDescribeRequest(opts itemDescribeRequestBuildOptions) (request.ItemDescribeRequest, error) {
	cwd, err := normalizeCWD(opts.cwd)
	if err != nil {
		return request.ItemDescribeRequest{}, err
	}
	resolvedExecutable := opts.resolvedExecutable
	if resolvedExecutable == "" {
		resolvedExecutable, err = os.Executable()
		if err != nil {
			return request.ItemDescribeRequest{}, fmt.Errorf("resolve current executable: %w", err)
		}
	}
	resolvedExecutable, err = validateExecutable(resolvedExecutable)
	if err != nil {
		return request.ItemDescribeRequest{}, err
	}

	return request.NewItemDescribe(request.ItemDescribeOptions{
		Reason:             opts.reason,
		Command:            opts.command,
		CWD:                cwd,
		ResolvedExecutable: resolvedExecutable,
		Ref:                opts.ref,
		Account:            opts.account,
		TTL:                opts.ttl,
	})
}

func normalizeCWD(cwd string) (string, error) {
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get current working directory: %w", err)
		}
	}

	resolved, err := pathresolve.Strict(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat cwd %q: %w", resolved, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cwd %q is not a directory", resolved)
	}

	return resolved, nil
}

func resolveCommand(cwd string, env []string, command []string) ([]string, string, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, "", fmt.Errorf("%w: argv is required", request.ErrInvalidCommand)
	}

	argv := slices.Clone(command)
	executable := argv[0]
	var candidate string

	if strings.ContainsRune(executable, '/') {
		if filepath.IsAbs(executable) {
			candidate = executable
		} else {
			candidate = filepath.Join(cwd, executable)
		}
		resolved, err := validateExecutable(candidate)
		if err != nil {
			return nil, "", err
		}
		return argv, resolved, nil
	}

	pathValue := lookupEnv(env, "PATH")
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" {
			dir = "."
		}
		candidate = filepath.Join(dir, executable)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		resolved, err := validateExecutable(candidate)
		if err == nil {
			return argv, resolved, nil
		}
	}

	return nil, "", fmt.Errorf("%w: executable %q not found in caller PATH", request.ErrInvalidCommand, executable)
}

func validateExecutable(path string) (string, error) {
	resolved, err := pathresolve.Strict(path)
	if err != nil {
		return "", fmt.Errorf("%w: resolve executable %q: %w", request.ErrInvalidCommand, path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: stat executable %q: %w", request.ErrInvalidCommand, resolved, err)
	}
	if info.IsDir() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%w: %q is not executable", request.ErrInvalidCommand, resolved)
	}
	return resolved, nil
}

func detectOverrides(env []string, secrets []request.Secret, override bool) ([]string, error) {
	present := make(map[string]struct{}, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			present[key] = struct{}{}
		}
	}

	overridden := make([]string, 0)
	for _, secret := range secrets {
		if _, exists := present[secret.Alias]; exists {
			if !override {
				return nil, fmt.Errorf(
					"%w: existing environment variable %q requires override",
					request.ErrInvalidAlias,
					secret.Alias,
				)
			}
			overridden = append(overridden, secret.Alias)
		}
	}
	slices.Sort(overridden)

	return overridden, nil
}

func lookupEnv(env []string, key string) string {
	for _, entry := range env {
		gotKey, value, ok := strings.Cut(entry, "=")
		if ok && gotKey == key {
			return value
		}
	}
	return ""
}
