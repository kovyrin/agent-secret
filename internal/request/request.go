package request

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

const (
	MaxReasonLength = 240
	DefaultExecTTL  = 2 * time.Minute
	MinExecTTL      = 10 * time.Second
	MaxExecTTL      = 10 * time.Minute
)

var (
	ErrInvalidAlias        = errors.New("invalid secret alias")
	ErrInvalidCommand      = errors.New("invalid command")
	ErrInvalidDeliveryMode = errors.New("invalid delivery mode")
	ErrInvalidMaxReads     = errors.New("invalid max reads")
	ErrMutableExecutable   = errors.New("mutable executable requires explicit opt-in")
	ErrInvalidReason       = errors.New("invalid reason")
	ErrInvalidReference    = errors.New("invalid 1Password secret reference")
	ErrInvalidRequest      = errors.New("invalid exec request")
	ErrInvalidTTL          = errors.New("invalid ttl")
)

var aliasPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type DeliveryMode string

const (
	DeliveryEnvExec       DeliveryMode = "env_exec"
	DeliverySessionSocket DeliveryMode = "session_socket"
)

type SecretSpec struct {
	Alias   string
	Ref     string
	Account string
}

type SecretRef struct {
	Raw     string
	Vault   string
	Item    string
	Section string
	Field   string
}

type Secret struct {
	Alias   string
	Ref     SecretRef
	Account string
}

type ExecOptions struct {
	Reason                 string
	Command                []string
	CWD                    string
	Env                    []string
	Secrets                []SecretSpec
	TTL                    time.Duration
	ReceivedAt             time.Time
	DeliveryMode           DeliveryMode
	MaxReads               int
	OverrideEnv            bool
	ForceRefresh           bool
	AllowMutableExecutable bool
}

type ExecRequest struct {
	Reason                 string
	Command                []string
	ResolvedExecutable     string
	ExecutableIdentity     fileidentity.Identity
	CWD                    string
	Env                    []string `json:"-"`
	Secrets                []Secret
	TTL                    time.Duration
	ReceivedAt             time.Time
	ExpiresAt              time.Time
	DeliveryMode           DeliveryMode
	MaxReads               int
	OverrideEnv            bool
	OverriddenAliases      []string
	ForceRefresh           bool
	AllowMutableExecutable bool
}

func (r ExecRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r ExecRequest) ValidateForDaemon() error {
	reason, err := validateReason(r.Reason)
	if err != nil {
		return err
	}
	if reason != r.Reason {
		return fmt.Errorf("%w: reason must be pre-normalized", ErrInvalidReason)
	}
	if r.DeliveryMode == DeliverySessionSocket {
		return fmt.Errorf("%w: daemon does not implement %q delivery", ErrInvalidDeliveryMode, r.DeliveryMode)
	}
	if err := validateDelivery(r.DeliveryMode, r.MaxReads); err != nil {
		return err
	}
	if r.TTL < MinExecTTL || r.TTL > MaxExecTTL {
		return fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinExecTTL, MaxExecTTL)
	}
	if r.ReceivedAt.IsZero() || r.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: request times are required", ErrInvalidRequest)
	}
	if !r.ExpiresAt.Equal(r.ReceivedAt.Add(r.TTL)) {
		return fmt.Errorf("%w: expires_at must equal received_at plus ttl", ErrInvalidTTL)
	}
	if err := validateDaemonPath("cwd", r.CWD, false); err != nil {
		return err
	}
	if err := validateDaemonPath("resolved executable", r.ResolvedExecutable, true); err != nil {
		return err
	}
	if r.ExecutableIdentity.IsZero() {
		return fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if len(r.Command) == 0 || r.Command[0] == "" {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if _, err := validateDaemonSecrets(r.Secrets); err != nil {
		return err
	}
	if err := validateOverriddenAliases(r.Secrets, r.OverriddenAliases, r.OverrideEnv); err != nil {
		return err
	}
	return nil
}

func NewExec(opts ExecOptions) (ExecRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return ExecRequest{}, err
	}

	mode := opts.DeliveryMode
	if mode == "" {
		mode = DeliveryEnvExec
	}
	if err := validateDelivery(mode, opts.MaxReads); err != nil {
		return ExecRequest{}, err
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultExecTTL
	}
	if ttl < MinExecTTL || ttl > MaxExecTTL {
		return ExecRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinExecTTL, MaxExecTTL)
	}

	receivedAt := opts.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}

	cwd, err := normalizeCWD(opts.CWD)
	if err != nil {
		return ExecRequest{}, err
	}

	env := opts.Env
	if env == nil {
		env = os.Environ()
	}
	env = slices.Clone(env)

	command, resolved, err := resolveCommand(cwd, env, opts.Command)
	if err != nil {
		return ExecRequest{}, err
	}
	executableIdentity, err := fileidentity.Capture(resolved)
	if err != nil {
		return ExecRequest{}, fmt.Errorf("%w: capture executable identity: %w", ErrInvalidCommand, err)
	}
	if !opts.AllowMutableExecutable {
		if err := fileidentity.ValidateStableExecutable(resolved); err != nil {
			return ExecRequest{}, fmt.Errorf("%w: %w", ErrMutableExecutable, err)
		}
	}

	secrets, err := parseSecrets(opts.Secrets)
	if err != nil {
		return ExecRequest{}, err
	}

	overriddenAliases, err := detectOverrides(env, secrets, opts.OverrideEnv)
	if err != nil {
		return ExecRequest{}, err
	}

	return ExecRequest{
		Reason:                 reason,
		Command:                command,
		ResolvedExecutable:     resolved,
		ExecutableIdentity:     executableIdentity,
		CWD:                    cwd,
		Env:                    env,
		Secrets:                secrets,
		TTL:                    ttl,
		ReceivedAt:             receivedAt,
		ExpiresAt:              receivedAt.Add(ttl),
		DeliveryMode:           mode,
		MaxReads:               opts.MaxReads,
		OverrideEnv:            opts.OverrideEnv,
		OverriddenAliases:      overriddenAliases,
		ForceRefresh:           opts.ForceRefresh,
		AllowMutableExecutable: opts.AllowMutableExecutable,
	}, nil
}

func ParseSecretRef(ref string) (SecretRef, error) {
	if strings.TrimSpace(ref) != ref || ref == "" {
		return SecretRef{}, fmt.Errorf("%w: must be non-empty and untrimmed", ErrInvalidReference)
	}
	if !strings.HasPrefix(ref, "op://") {
		return SecretRef{}, fmt.Errorf("%w: must start with op://", ErrInvalidReference)
	}

	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 3 || len(parts) > 4 {
		return SecretRef{}, fmt.Errorf("%w: expected op://vault/item[/section]/field-or-text-file", ErrInvalidReference)
	}
	if slices.Contains(parts, "") {
		return SecretRef{}, fmt.Errorf("%w: path segments must be non-empty", ErrInvalidReference)
	}

	secretRef := SecretRef{
		Raw:   ref,
		Vault: parts[0],
		Item:  parts[1],
		Field: parts[len(parts)-1],
	}
	if len(parts) == 4 {
		secretRef.Section = parts[2]
	}

	return secretRef, nil
}

func validateReason(reason string) (string, error) {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "", fmt.Errorf("%w: required", ErrInvalidReason)
	}
	if len([]rune(trimmed)) > MaxReasonLength {
		return "", fmt.Errorf("%w: maximum length is %d characters", ErrInvalidReason, MaxReasonLength)
	}
	return trimmed, nil
}

func validateDelivery(mode DeliveryMode, maxReads int) error {
	switch mode {
	case DeliveryEnvExec:
		if maxReads != 0 {
			return fmt.Errorf("%w: max reads is session/socket-only", ErrInvalidMaxReads)
		}
	case DeliverySessionSocket:
		if maxReads <= 0 {
			return fmt.Errorf("%w: session/socket reads require a positive max reads", ErrInvalidMaxReads)
		}
	default:
		return fmt.Errorf("%w: %q", ErrInvalidDeliveryMode, mode)
	}
	return nil
}

func normalizeCWD(cwd string) (string, error) {
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get current working directory: %w", err)
		}
	}

	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat cwd %q: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("cwd %q is not a directory", abs)
	}

	return evalPath(abs), nil
}

func resolveCommand(cwd string, env []string, command []string) ([]string, string, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, "", fmt.Errorf("%w: argv is required", ErrInvalidCommand)
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

	return nil, "", fmt.Errorf("%w: executable %q not found in caller PATH", ErrInvalidCommand, executable)
}

func validateExecutable(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: resolve executable %q: %w", ErrInvalidCommand, path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("%w: stat executable %q: %w", ErrInvalidCommand, abs, err)
	}
	if info.IsDir() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%w: %q is not executable", ErrInvalidCommand, abs)
	}
	return evalPath(abs), nil
}

func validateDaemonPath(name string, path string, executable bool) error {
	if path == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidRequest, name)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s must be absolute", ErrInvalidRequest, name)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%w: %s must be normalized", ErrInvalidRequest, name)
	}
	if executable && strings.HasSuffix(path, string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s must name a file", ErrInvalidCommand, name)
	}
	return nil
}

func parseSecrets(specs []SecretSpec) ([]Secret, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%w: at least one secret is required", ErrInvalidReference)
	}

	seenAliases := make(map[string]struct{}, len(specs))
	secrets := make([]Secret, 0, len(specs))
	for _, spec := range specs {
		if !aliasPattern.MatchString(spec.Alias) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidAlias, spec.Alias)
		}
		if _, exists := seenAliases[spec.Alias]; exists {
			return nil, fmt.Errorf("%w: duplicate alias %q", ErrInvalidAlias, spec.Alias)
		}
		seenAliases[spec.Alias] = struct{}{}

		ref, err := ParseSecretRef(spec.Ref)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, Secret{Alias: spec.Alias, Ref: ref, Account: strings.TrimSpace(spec.Account)})
	}

	return secrets, nil
}

func validateDaemonSecrets(secrets []Secret) ([]Secret, error) {
	specs := make([]SecretSpec, 0, len(secrets))
	for _, secret := range secrets {
		parsed, err := ParseSecretRef(secret.Ref.Raw)
		if err != nil {
			return nil, err
		}
		if parsed != secret.Ref {
			return nil, fmt.Errorf("%w: parsed reference metadata does not match raw ref", ErrInvalidReference)
		}
		specs = append(specs, SecretSpec{Alias: secret.Alias, Ref: secret.Ref.Raw, Account: secret.Account})
	}
	parsed, err := parseSecrets(specs)
	if err != nil {
		return nil, err
	}
	if len(parsed) != len(secrets) {
		return nil, fmt.Errorf("%w: secret count mismatch", ErrInvalidReference)
	}
	for i := range parsed {
		if parsed[i] != secrets[i] {
			return nil, fmt.Errorf("%w: secret metadata must be pre-normalized", ErrInvalidReference)
		}
	}
	return parsed, nil
}

func validateOverriddenAliases(secrets []Secret, aliases []string, override bool) error {
	if len(aliases) == 0 {
		return nil
	}
	if !override {
		return fmt.Errorf("%w: overridden aliases require override", ErrInvalidAlias)
	}
	if !slices.IsSorted(aliases) {
		return fmt.Errorf("%w: overridden aliases must be sorted", ErrInvalidAlias)
	}
	known := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		known[secret.Alias] = struct{}{}
	}
	seen := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		if !aliasPattern.MatchString(alias) {
			return fmt.Errorf("%w: %q", ErrInvalidAlias, alias)
		}
		if _, exists := seen[alias]; exists {
			return fmt.Errorf("%w: duplicate overridden alias %q", ErrInvalidAlias, alias)
		}
		seen[alias] = struct{}{}
		if _, exists := known[alias]; !exists {
			return fmt.Errorf("%w: overridden alias %q is not requested", ErrInvalidAlias, alias)
		}
	}
	return nil
}

func detectOverrides(env []string, secrets []Secret, override bool) ([]string, error) {
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
				return nil, fmt.Errorf("%w: existing environment variable %q requires override", ErrInvalidAlias, secret.Alias)
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

func evalPath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
