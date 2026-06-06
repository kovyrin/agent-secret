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
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
	"github.com/kovyrin/agent-secret/internal/executabletrust"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretref"
)

const DefaultBWSBinary = "bws"
const bitwardenDeveloperIDTeamID = "LTZ2PFU5D6"
const defaultBWSServerBase = "https://vault.bitwarden.com"
const isolatedBWSProfile = "agent-secret"

type CommandRunner interface {
	Run(ctx context.Context, binary string, args []string, env []string) ([]byte, error)
}

type PathSignatureVerifier interface {
	VerifyPath(path string) (string, error)
}

type ExecCommandRunner struct{}

type Resolver struct {
	Store             Store
	Binary            string
	Runner            CommandRunner
	CommonBinaryPaths func() []string
	BWSVerifier       PathSignatureVerifier
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
	if source.APIURL != "" || source.IdentityURL != "" {
		return "", fmt.Errorf("%w: custom Bitwarden endpoints are not supported in v1", ErrUnsupportedEndpoint)
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
	binary, err = resolveBWSBinary(binary, r.commonBinaryPaths(), r.bwsVerifier())
	if err != nil {
		return "", err
	}
	runner := r.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	configPath, cleanup, err := createIsolatedBWSConfig()
	if err != nil {
		return "", err
	}
	defer cleanup()
	args := []string{
		"--config-file",
		configPath,
		"--profile",
		isolatedBWSProfile,
		"secret",
		"get",
		secret.Ref.SecretID,
		"--output",
		"json",
		"--color",
		"no",
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
		return nil, fmt.Errorf("%w: install `bws` at a trusted system path such as /opt/homebrew/bin/bws or /usr/local/bin/bws", ErrBWSUnavailable)
	}
	message := bwsFailureMessage(stderr.String(), err.Error())
	return nil, fmt.Errorf("%w: bws secret get failed: %s", ErrBWSUnavailable, message)
}

func (r *Resolver) commonBinaryPaths() []string {
	if r.CommonBinaryPaths != nil {
		return r.CommonBinaryPaths()
	}
	return defaultCommonBWSBinaryPaths()
}

func (r *Resolver) bwsVerifier() PathSignatureVerifier {
	if r.BWSVerifier != nil {
		return r.BWSVerifier
	}
	return trust.CodesignSignatureVerifier{}
}

func resolveBWSBinary(binary string, commonPaths []string, verifier PathSignatureVerifier) (string, error) {
	if strings.ContainsRune(binary, os.PathSeparator) {
		resolved, found, err := validateTrustedBWSBinary(binary, verifier)
		if err != nil {
			return "", err
		}
		if !found {
			return "", fmt.Errorf("%w: bws helper %q does not exist", ErrBWSUnavailable, binary)
		}
		return resolved, nil
	}
	if binary != DefaultBWSBinary {
		return "", fmt.Errorf("%w: custom bws helper names are not supported; use an absolute trusted path", ErrBWSUnavailable)
	}
	var firstErr error
	for _, candidate := range commonPaths {
		resolved, found, err := validateTrustedBWSBinary(candidate, verifier)
		if err == nil && found {
			return resolved, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", fmt.Errorf("%w: install `bws` at a trusted system path such as /opt/homebrew/bin/bws or /usr/local/bin/bws", ErrBWSUnavailable)
}

func defaultCommonBWSBinaryPaths() []string {
	return []string{
		"/opt/homebrew/bin/bws",
		"/usr/local/bin/bws",
	}
}

func validateTrustedBWSBinary(path string, verifier PathSignatureVerifier) (string, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false, nil
	}
	if !strings.ContainsRune(path, os.PathSeparator) {
		return "", false, fmt.Errorf("%w: bws helper path %q is not absolute", ErrBWSUnavailable, path)
	}
	if !filepath.IsAbs(path) {
		return "", false, fmt.Errorf("%w: bws helper path %q is not absolute", ErrBWSUnavailable, path)
	}
	resolved, err := pathresolve.Strict(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("%w: resolve bws helper %q: %w", ErrBWSUnavailable, path, err)
	}
	if err := executabletrust.ValidateStableExecutable(resolved); err == nil {
		return resolved, true, nil
	} else if !isBitwardenSignedBWSBinary(resolved, verifier) {
		return "", true, fmt.Errorf("%w: untrusted bws helper %q: %w", ErrBWSUnavailable, resolved, err)
	}
	return resolved, true, nil
}

func isBitwardenSignedBWSBinary(path string, verifier PathSignatureVerifier) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	if verifier == nil {
		verifier = trust.CodesignSignatureVerifier{}
	}
	teamID, err := verifier.VerifyPath(path)
	return err == nil && teamID == bitwardenDeveloperIDTeamID
}

func bwsEnvironment(accessToken string) []string {
	return []string{
		"BWS_ACCESS_TOKEN=" + accessToken,
		"NO_COLOR=1",
	}
}

func createIsolatedBWSConfig() (string, func(), error) {
	dir, err := os.MkdirTemp("", "agent-secret-bws-")
	if err != nil {
		return "", func() {}, fmt.Errorf("%w: create isolated bws config: %w", ErrBWSUnavailable, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "config")
	config := fmt.Sprintf(
		"[profiles.%s]\nserver_base = %q\nstate_opt_out = \"true\"\n",
		isolatedBWSProfile,
		defaultBWSServerBase,
	)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("%w: write isolated bws config: %w", ErrBWSUnavailable, err)
	}
	return path, cleanup, nil
}

func bwsFailureMessage(stderr string, fallback string) string {
	fallback = strings.TrimSpace(fallback)
	for line := range strings.SplitSeq(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Error:" {
			continue
		}
		if line == "Location:" || strings.HasPrefix(line, "Backtrace ") ||
			strings.HasPrefix(line, "Run with RUST_BACKTRACE=") {
			break
		}
		return stripBWSDiagnosticPrefix(line)
	}
	if fallback != "" {
		return fallback
	}
	return "unknown error"
}

func stripBWSDiagnosticPrefix(line string) string {
	prefix, message, ok := strings.Cut(line, ":")
	if !ok {
		return line
	}
	prefix = strings.TrimSpace(prefix)
	message = strings.TrimSpace(message)
	if message == "" {
		return line
	}
	if strings.EqualFold(prefix, "error") {
		return message
	}
	for _, r := range prefix {
		if r < '0' || r > '9' {
			return line
		}
	}
	return message
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
