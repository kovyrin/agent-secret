package request

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/executabletrust"
	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/secretref"
)

const (
	MaxReasonLength     = 240
	DefaultExecTTL      = 2 * time.Minute
	MinRequestTTL       = 10 * time.Second
	MaxRequestTTL       = 10 * time.Minute
	DefaultReusableUses = 3
	MaxReusableUses     = 20
)

var (
	ErrInvalidAlias        = errors.New("invalid secret alias")
	ErrInvalidCommand      = errors.New("invalid command")
	ErrInvalidReason       = errors.New("invalid reason")
	ErrInvalidReference    = errors.New("invalid secret reference")
	ErrInvalidReusableUses = errors.New("invalid reusable use count")
	ErrInvalidRequest      = errors.New("invalid request")
	ErrInvalidTTL          = errors.New("invalid ttl")
)

var aliasPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

type SecretSpec struct {
	Alias     string          `json:"alias"`
	Ref       string          `json:"ref"`
	Account   string          `json:"account,omitempty"`
	Source    string          `json:"source,omitempty"`
	Bitwarden BitwardenSource `json:"bitwarden,omitzero"`
}

type SecretRef struct {
	Raw      string `json:"raw"`
	Provider string `json:"provider,omitempty"`
	Vault    string `json:"vault,omitempty"`
	Item     string `json:"item,omitempty"`
	Section  string `json:"section,omitempty"`
	Field    string `json:"field,omitempty"`
	Source   string `json:"source,omitempty"`
	SecretID string `json:"secret_id,omitempty"`
}

type BitwardenSource struct {
	Alias       string `json:"alias,omitempty"`
	TokenAlias  string `json:"token_alias,omitempty"`
	APIURL      string `json:"api_url,omitempty"`
	IdentityURL string `json:"identity_url,omitempty"`
}

func (s BitwardenSource) IsZero() bool {
	return s == BitwardenSource{}
}

type Secret struct {
	Alias     string          `json:"alias"`
	Ref       SecretRef       `json:"ref"`
	Account   string          `json:"account,omitempty"`
	Source    string          `json:"source,omitempty"`
	Bitwarden BitwardenSource `json:"bitwarden,omitzero"`
}

type ExecOptions struct {
	Reason                 string
	Command                []string
	ResolvedExecutable     string
	ExecutableIdentity     fileidentity.Identity
	AllowMutableExecutable bool
	CWD                    string
	EnvironmentFingerprint string
	Secrets                []SecretSpec
	TTL                    time.Duration
	ReceivedAt             time.Time
	ReusableUses           int
	OverrideEnv            bool
	OverriddenAliases      []string
	ForceRefresh           bool
	ReuseOnly              bool
}

type ExecRequest struct {
	Reason                 string                `json:"reason"`
	Command                []string              `json:"command"`
	ResolvedExecutable     string                `json:"resolved_executable"`
	ExecutableIdentity     fileidentity.Identity `json:"executable_identity"`
	AllowMutableExecutable bool                  `json:"allow_mutable_executable"`
	CWD                    string                `json:"cwd"`
	EnvironmentFingerprint string                `json:"environment_fingerprint"`
	Secrets                []Secret              `json:"secrets"`
	TTL                    time.Duration         `json:"ttl"`
	ReceivedAt             time.Time             `json:"received_at"`
	ExpiresAt              time.Time             `json:"expires_at"`
	ReusableUses           int                   `json:"reusable_uses"`
	OverrideEnv            bool                  `json:"override_env"`
	OverriddenAliases      []string              `json:"overridden_aliases"`
	ForceRefresh           bool                  `json:"force_refresh"`
	ReuseOnly              bool                  `json:"reuse_only,omitempty"`
}

func SecretAliases(secrets []Secret) []string {
	aliases := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		aliases = append(aliases, secret.Alias)
	}
	slices.Sort(aliases)
	return aliases
}

func (r ExecRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r ExecRequest) WithReceiptTime(receivedAt time.Time) ExecRequest {
	r.ReceivedAt = receivedAt
	r.ExpiresAt = receivedAt.Add(r.TTL)
	return r
}

func (r ExecRequest) ValidateForDaemon() error {
	if err := validateReusableUses(r.ReusableUses); err != nil {
		return err
	}
	if r.ExecutableIdentity.IsZero() {
		return fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if err := validateEnvironmentFingerprint(r.EnvironmentFingerprint); err != nil {
		return err
	}
	if err := validateDaemonPreparedPath("cwd", r.CWD, false); err != nil {
		return err
	}
	if err := validateDaemonPreparedPath("resolved executable", r.ResolvedExecutable, true); err != nil {
		return err
	}
	if err := fileidentity.Verify(r.ResolvedExecutable, r.ExecutableIdentity); err != nil {
		return fmt.Errorf("%w: executable identity changed: %w", ErrInvalidRequest, err)
	}
	if !r.AllowMutableExecutable {
		if err := executabletrust.ValidateStableExecutable(r.ResolvedExecutable); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
	}
	if err := validateDaemonLifecycle(daemonLifecycle{
		Reason:             r.Reason,
		Command:            r.Command,
		CWD:                r.CWD,
		ResolvedExecutable: r.ResolvedExecutable,
		TTL:                r.TTL,
		ReceivedAt:         r.ReceivedAt,
		ExpiresAt:          r.ExpiresAt,
	}); err != nil {
		return err
	}
	if _, err := validateDaemonSecrets(r.Secrets); err != nil {
		return err
	}
	if err := validateOverriddenAliases(r.Secrets, r.OverriddenAliases, r.OverrideEnv); err != nil {
		return err
	}
	return nil
}

type daemonLifecycle struct {
	Reason             string
	Command            []string
	CWD                string
	ResolvedExecutable string
	TTL                time.Duration
	ReceivedAt         time.Time
	ExpiresAt          time.Time
}

func validateDaemonLifecycle(lifecycle daemonLifecycle) error {
	reason, err := validateReason(lifecycle.Reason)
	if err != nil {
		return err
	}
	if reason != lifecycle.Reason {
		return fmt.Errorf("%w: reason must be pre-normalized", ErrInvalidReason)
	}
	if lifecycle.TTL < MinRequestTTL || lifecycle.TTL > MaxRequestTTL {
		return fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxRequestTTL)
	}
	if lifecycle.ReceivedAt.IsZero() || lifecycle.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: request times are required", ErrInvalidRequest)
	}
	if !lifecycle.ExpiresAt.Equal(lifecycle.ReceivedAt.Add(lifecycle.TTL)) {
		return fmt.Errorf("%w: expires_at must equal received_at plus ttl", ErrInvalidTTL)
	}
	if err := validatePreparedPath("cwd", lifecycle.CWD, false); err != nil {
		return err
	}
	if err := validatePreparedPath("resolved executable", lifecycle.ResolvedExecutable, true); err != nil {
		return err
	}
	if len(lifecycle.Command) == 0 || lifecycle.Command[0] == "" {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	return nil
}

func NewExec(opts ExecOptions) (ExecRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return ExecRequest{}, err
	}

	reusableUses := ReusableUsesOrDefault(opts.ReusableUses)
	if err := validateReusableUses(reusableUses); err != nil {
		return ExecRequest{}, err
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultExecTTL
	}
	if ttl < MinRequestTTL || ttl > MaxRequestTTL {
		return ExecRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxRequestTTL)
	}

	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}

	command := slices.Clone(opts.Command)
	if len(command) == 0 || command[0] == "" {
		return ExecRequest{}, fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if err := validatePreparedPath("cwd", opts.CWD, false); err != nil {
		return ExecRequest{}, err
	}
	if err := validatePreparedPath("resolved executable", opts.ResolvedExecutable, true); err != nil {
		return ExecRequest{}, err
	}
	if opts.ExecutableIdentity.IsZero() {
		return ExecRequest{}, fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if err := validateEnvironmentFingerprint(opts.EnvironmentFingerprint); err != nil {
		return ExecRequest{}, err
	}
	secrets, err := ParseSecrets(opts.Secrets)
	if err != nil {
		return ExecRequest{}, err
	}

	overriddenAliases := slices.Clone(opts.OverriddenAliases)
	if err := validateOverriddenAliases(secrets, overriddenAliases, opts.OverrideEnv); err != nil {
		return ExecRequest{}, err
	}

	return ExecRequest{
		Reason:                 reason,
		Command:                command,
		ResolvedExecutable:     opts.ResolvedExecutable,
		ExecutableIdentity:     opts.ExecutableIdentity,
		AllowMutableExecutable: opts.AllowMutableExecutable,
		CWD:                    opts.CWD,
		EnvironmentFingerprint: opts.EnvironmentFingerprint,
		Secrets:                secrets,
		TTL:                    ttl,
		ReceivedAt:             receivedAt,
		ExpiresAt:              expiresAt,
		ReusableUses:           reusableUses,
		OverrideEnv:            opts.OverrideEnv,
		OverriddenAliases:      overriddenAliases,
		ForceRefresh:           opts.ForceRefresh,
		ReuseOnly:              opts.ReuseOnly,
	}, nil
}

func EnvironmentFingerprint(env []string) string {
	canonical := canonicalEnv(env)
	sum := sha256.New()
	for _, entry := range canonical {
		sum.Write([]byte(entry))
		sum.Write([]byte{0})
	}
	return "env-v1:" + hex.EncodeToString(sum.Sum(nil))
}

func ReusableUsesOrDefault(uses int) int {
	if uses == 0 {
		return DefaultReusableUses
	}
	return uses
}

func ParseSecretRef(ref string) (SecretRef, error) {
	parsed, err := secretref.Parse(ref)
	if err != nil {
		return SecretRef{}, fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}
	return SecretRef{
		Raw:      parsed.Raw,
		Provider: parsed.Provider,
		Vault:    parsed.Vault,
		Item:     parsed.Item,
		Section:  parsed.Section,
		Field:    parsed.Field,
		Source:   parsed.Source,
		SecretID: parsed.SecretID,
	}, nil
}

func ValidateReason(reason string) error {
	_, err := validateReason(reason)
	return err
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

func validateReusableUses(uses int) error {
	uses = ReusableUsesOrDefault(uses)
	if uses < 1 || uses > MaxReusableUses {
		return fmt.Errorf("%w: must be between 1 and %d", ErrInvalidReusableUses, MaxReusableUses)
	}
	return nil
}

func validatePreparedPath(name string, path string, executable bool) error {
	if path == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidRequest, name)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s must be absolute", ErrInvalidRequest, name)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%w: %s must be normalized", ErrInvalidRequest, name)
	}
	if executable && strings.HasSuffix(path, "/") {
		return fmt.Errorf("%w: %s must name a file", ErrInvalidCommand, name)
	}
	return nil
}

func validateDaemonPreparedPath(name string, path string, executable bool) error {
	if err := validatePreparedPath(name, path, executable); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: %s must exist and be symlink-resolved: %w", ErrInvalidRequest, name, err)
	}
	if resolved != path {
		return fmt.Errorf("%w: %s must be symlink-resolved", ErrInvalidRequest, name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: %s must exist: %w", ErrInvalidRequest, name, err)
	}
	if executable {
		if info.IsDir() {
			return fmt.Errorf("%w: %s must name a file", ErrInvalidCommand, name)
		}
		if info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%w: %s must be executable", ErrInvalidCommand, name)
		}
		return nil
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s must name a directory", ErrInvalidRequest, name)
	}
	return nil
}

func ParseSecrets(specs []SecretSpec) ([]Secret, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%w: at least one secret is required", ErrInvalidReference)
	}

	seenAliases := make(map[string]struct{}, len(specs))
	secrets := make([]Secret, 0, len(specs))
	for _, spec := range specs {
		if !aliasPattern.MatchString(spec.Alias) {
			return nil, fmt.Errorf("%w: alias must match [A-Z_][A-Z0-9_]*, for example API_TOKEN (got: %q)", ErrInvalidAlias, spec.Alias)
		}
		if _, exists := seenAliases[spec.Alias]; exists {
			return nil, fmt.Errorf("%w: duplicate alias %q", ErrInvalidAlias, spec.Alias)
		}
		seenAliases[spec.Alias] = struct{}{}

		ref, err := ParseSecretRef(spec.Ref)
		if err != nil {
			return nil, err
		}
		account := strings.TrimSpace(spec.Account)
		source := strings.TrimSpace(spec.Source)
		bitwardenSource := spec.Bitwarden
		switch ref.Provider {
		case secretref.ProviderOnePassword:
			if account == "" {
				return nil, fmt.Errorf("%w: account is required for 1Password refs", ErrInvalidReference)
			}
			if source != "" {
				return nil, fmt.Errorf("%w: source is only valid for Bitwarden refs", ErrInvalidReference)
			}
			if bitwardenSource != (BitwardenSource{}) {
				return nil, fmt.Errorf("%w: Bitwarden source metadata is only valid for Bitwarden refs", ErrInvalidReference)
			}
		case secretref.ProviderBitwardenSecretsManager:
			normalized, err := normalizeBitwardenSecretSource(ref, source, bitwardenSource)
			if err != nil {
				return nil, err
			}
			source = normalized.Alias
			bitwardenSource = normalized
			if account != "" {
				return nil, fmt.Errorf("%w: account is only valid for 1Password refs", ErrInvalidReference)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported secret provider %q", ErrInvalidReference, ref.Provider)
		}
		secrets = append(secrets, Secret{
			Alias:     spec.Alias,
			Ref:       ref,
			Account:   account,
			Source:    source,
			Bitwarden: bitwardenSource,
		})
	}

	return secrets, nil
}

func validateDaemonSecrets(secrets []Secret) ([]Secret, error) {
	specs := make([]SecretSpec, 0, len(secrets))
	for _, secret := range secrets {
		if strings.TrimSpace(secret.Account) != secret.Account {
			return nil, fmt.Errorf("%w: secret %q account must be trimmed", ErrInvalidReference, secret.Alias)
		}
		if strings.TrimSpace(secret.Source) != secret.Source {
			return nil, fmt.Errorf("%w: secret %q source must be trimmed", ErrInvalidReference, secret.Alias)
		}
		parsed, err := ParseSecretRef(secret.Ref.Raw)
		if err != nil {
			return nil, err
		}
		if parsed != secret.Ref {
			return nil, fmt.Errorf("%w: parsed reference metadata does not match raw ref", ErrInvalidReference)
		}
		specs = append(specs, SecretSpec{
			Alias:     secret.Alias,
			Ref:       secret.Ref.Raw,
			Account:   secret.Account,
			Source:    secret.Source,
			Bitwarden: secret.Bitwarden,
		})
	}
	parsed, err := ParseSecrets(specs)
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

func normalizeBitwardenSecretSource(ref SecretRef, source string, metadata BitwardenSource) (BitwardenSource, error) {
	if ref.Source != "" {
		if source != "" && source != ref.Source {
			return BitwardenSource{}, fmt.Errorf(
				"%w: Bitwarden source %q does not match ref source %q",
				ErrInvalidReference,
				source,
				ref.Source,
			)
		}
		source = ref.Source
	}
	if metadata.Alias != "" {
		alias, err := secretref.NormalizeSourceAlias(metadata.Alias)
		if err != nil {
			return BitwardenSource{}, err
		}
		if source != "" && alias != source {
			return BitwardenSource{}, fmt.Errorf(
				"%w: Bitwarden source metadata alias %q does not match source %q",
				ErrInvalidReference,
				alias,
				source,
			)
		}
		source = alias
	}
	if source == "" {
		return BitwardenSource{}, fmt.Errorf(
			"%w: Bitwarden refs require a source; use bws://<source-alias>/<secret-uuid> or configure one Bitwarden source",
			ErrInvalidReference,
		)
	}
	alias, err := secretref.NormalizeSourceAlias(source)
	if err != nil {
		return BitwardenSource{}, err
	}
	tokenAlias := strings.TrimSpace(metadata.TokenAlias)
	if tokenAlias == "" {
		tokenAlias = alias
	}
	tokenAlias, err = secretref.NormalizeSourceAlias(tokenAlias)
	if err != nil {
		return BitwardenSource{}, fmt.Errorf("%w: invalid Bitwarden token alias: %w", ErrInvalidReference, err)
	}
	if strings.TrimSpace(metadata.APIURL) != "" || strings.TrimSpace(metadata.IdentityURL) != "" {
		return BitwardenSource{}, fmt.Errorf("%w: custom Bitwarden endpoints are not supported in v1", ErrInvalidReference)
	}
	return BitwardenSource{
		Alias:      alias,
		TokenAlias: tokenAlias,
	}, nil
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

func validateEnvironmentFingerprint(value string) error {
	const prefix = "env-v1:"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%w: environment fingerprint is required", ErrInvalidRequest)
	}
	raw := strings.TrimPrefix(value, prefix)
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%w: invalid environment fingerprint", ErrInvalidRequest)
	}
	return nil
}

func canonicalEnv(env []string) []string {
	values := make(map[string]string, len(env))
	malformed := make([]string, 0)
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			malformed = append(malformed, entry)
			continue
		}
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	out := make([]string, 0, len(keys)+len(malformed))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	slices.Sort(malformed)
	for _, entry := range malformed {
		out = append(out, "malformed:"+entry)
	}
	return out
}
