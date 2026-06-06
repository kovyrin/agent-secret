package bwsm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretref"
)

const DefaultBWSBinary = "bws"

type CommandRunner interface {
	Run(ctx context.Context, binary string, args []string, env []string) ([]byte, error)
}

type ExecCommandRunner struct{}

type Resolver struct {
	Store             Store
	Binary            string
	Runner            CommandRunner
	CommonBinaryPaths func() []string
}

type secretObject struct {
	Object string  `json:"object"`
	ID     string  `json:"id"`
	Value  *string `json:"value"`
}

func NewResolver(store Store) *Resolver {
	return &Resolver{Store: store, Binary: DefaultBWSBinary, Runner: ExecCommandRunner{}}
}

func (r *Resolver) ResolveSecret(ctx context.Context, secret request.Secret) (string, error) {
	if secret.Ref.Provider != secretref.ProviderBitwardenSecretsManager {
		return "", fmt.Errorf("%w: unsupported provider %q", ErrInvalidBWSOutput, secret.Ref.Provider)
	}
	if secret.Ref.SecretID == "" {
		return "", fmt.Errorf("%w: Bitwarden secret id is required", ErrInvalidBWSOutput)
	}
	source := secret.Bitwarden
	if source.Alias == "" {
		source.Alias = secret.Source
	}
	if source.TokenAlias == "" {
		source.TokenAlias = source.Alias
	}
	if source.TokenAlias == "" {
		return "", fmt.Errorf("%w: Bitwarden token alias is required", ErrInvalidTokenAlias)
	}
	store := r.Store
	if store == nil {
		store = NewKeychainStore("")
	}
	token, found, err := store.Get(ctx, source.TokenAlias)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%w: alias %q", ErrTokenNotFound, source.TokenAlias)
	}
	binary := strings.TrimSpace(r.Binary)
	if binary == "" {
		binary = DefaultBWSBinary
	}
	binary = resolveBWSBinary(binary, r.commonBinaryPaths())
	runner := r.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	args := []string{"secret", "get", secret.Ref.SecretID, "--output", "json", "--color", "no"}
	if source.APIURL != "" {
		args = append(args, "--server-url", source.APIURL)
	}
	output, err := runner.Run(ctx, binary, args, bwsEnvironment(token.AccessToken))
	if err != nil {
		return "", err
	}
	value, err := secretValueFromBWSOutput(output)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (ExecCommandRunner) Run(ctx context.Context, binary string, args []string, env []string) ([]byte, error) {
	//nolint:gosec // G204: binary is Agent Secret's configured bws path, args are fixed/value-free, and the token is passed only through child env.
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		return nil, fmt.Errorf("%w: install the `bws` CLI and ensure it is on the daemon PATH", ErrBWSUnavailable)
	}
	message := strings.TrimSpace(stderr.String())
	if message == "" {
		message = err.Error()
	}
	return nil, fmt.Errorf("%w: bws secret get failed: %s", ErrBWSUnavailable, message)
}

func (r *Resolver) commonBinaryPaths() []string {
	if r.CommonBinaryPaths != nil {
		return r.CommonBinaryPaths()
	}
	return defaultCommonBWSBinaryPaths()
}

func resolveBWSBinary(binary string, commonPaths []string) string {
	if strings.ContainsRune(binary, os.PathSeparator) {
		return binary
	}
	if resolved, err := exec.LookPath(binary); err == nil {
		return resolved
	}
	if binary != DefaultBWSBinary {
		return binary
	}
	for _, candidate := range commonPaths {
		if executableFileExists(candidate) {
			return candidate
		}
	}
	return binary
}

func defaultCommonBWSBinaryPaths() []string {
	paths := []string{
		"/opt/homebrew/bin/bws",
		"/usr/local/bin/bws",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".local", "bin", "bws"))
	}
	return paths
}

func executableFileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode().Perm()&0o111 != 0
}

func bwsEnvironment(accessToken string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			env = append(env, entry)
			continue
		}
		switch key {
		case "BWS_ACCESS_TOKEN":
			continue
		default:
			env = append(env, entry)
		}
	}
	env = append(env, "BWS_ACCESS_TOKEN="+accessToken)
	if !slices.ContainsFunc(env, func(entry string) bool {
		key, _, ok := strings.Cut(entry, "=")
		return ok && key == "NO_COLOR"
	}) {
		env = append(env, "NO_COLOR=1")
	}
	return env
}

func secretValueFromBWSOutput(output []byte) (string, error) {
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return "", fmt.Errorf("%w: empty bws response", ErrInvalidBWSOutput)
	}
	var object secretObject
	if err := json.Unmarshal(output, &object); err == nil && object.Value != nil {
		return *object.Value, nil
	}
	var objects []secretObject
	if err := json.Unmarshal(output, &objects); err == nil {
		if len(objects) != 1 {
			return "", fmt.Errorf("%w: expected one secret object, got %d", ErrInvalidBWSOutput, len(objects))
		}
		if objects[0].Value == nil {
			return "", fmt.Errorf("%w: secret object did not include value", ErrInvalidBWSOutput)
		}
		return *objects[0].Value, nil
	}
	return "", fmt.Errorf("%w: response was not a secret JSON object", ErrInvalidBWSOutput)
}
