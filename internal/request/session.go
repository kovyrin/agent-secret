package request

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

const (
	DefaultSessionTTL      = 2 * time.Minute
	DefaultSessionMaxReads = 1
	MaxSessionReads        = 100
	MaxSessionBindAncestor = 3
)

var (
	ErrInvalidSessionID    = fmt.Errorf("%w: invalid session id", ErrInvalidRequest)
	ErrInvalidSessionToken = fmt.Errorf("%w: invalid session token", ErrInvalidRequest)
	ErrInvalidSessionRead  = fmt.Errorf("%w: invalid session read count", ErrInvalidRequest)
	ErrInvalidSessionBind  = fmt.Errorf("%w: invalid session binding", ErrInvalidRequest)
)

var (
	sessionIDPattern    = regexp.MustCompile(`^asid_[A-Za-z0-9_-]+$`)
	sessionTokenPattern = regexp.MustCompile(`^astok_[A-Za-z0-9_-]+$`)
)

type SessionCreateOptions struct {
	Reason             string
	Command            []string
	ResolvedExecutable string
	ExecutableIdentity fileidentity.Identity
	CWD                string
	Secrets            []SecretSpec
	TTL                time.Duration
	ReceivedAt         time.Time
	MaxReads           int
	OverrideEnv        bool
	Binding            SessionBindingPolicy
}

type SessionCreateRequest struct {
	Reason             string                `json:"reason"`
	Command            []string              `json:"command"`
	ResolvedExecutable string                `json:"resolved_executable"`
	ExecutableIdentity fileidentity.Identity `json:"executable_identity"`
	CWD                string                `json:"cwd"`
	Secrets            []Secret              `json:"secrets"`
	TTL                time.Duration         `json:"ttl"`
	ReceivedAt         time.Time             `json:"received_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
	MaxReads           int                   `json:"max_reads"`
	OverrideEnv        bool                  `json:"override_env"`
	Binding            SessionBindingPolicy  `json:"session_binding"`
}

type SessionResolveRequest struct {
	SessionToken           string                `json:"session_token"`
	Command                []string              `json:"command"`
	ResolvedExecutable     string                `json:"resolved_executable"`
	ExecutableIdentity     fileidentity.Identity `json:"executable_identity"`
	CWD                    string                `json:"cwd"`
	EnvironmentFingerprint string                `json:"environment_fingerprint"`
	RequestedAliases       []string              `json:"requested_aliases,omitempty"`
	ExpectedPeer           peercred.Expected     `json:"expected_peer"`
}

type SessionDestroyRequest struct {
	SessionID string `json:"session_id,omitempty"`
	All       bool   `json:"all,omitempty"`
}

type SessionSummary struct {
	SessionID      string             `json:"session_id"`
	SessionToken   string             `json:"session_token,omitempty"`
	Reason         string             `json:"reason"`
	CWD            string             `json:"cwd"`
	SecretAliases  []string           `json:"secret_aliases"`
	ExpiresAt      time.Time          `json:"expires_at"`
	MaxReads       int                `json:"max_reads"`
	RemainingReads int                `json:"remaining_reads"`
	OverrideEnv    bool               `json:"override_env"`
	Binding        SessionBindingInfo `json:"session_binding"`
}

type SessionBindingMode string

const (
	SessionBindingModeAuto     SessionBindingMode = "auto"
	SessionBindingModeAncestor SessionBindingMode = "ancestor"
)

type SessionBindingPolicy struct {
	Mode          SessionBindingMode `json:"mode,omitempty"`
	AncestorDepth int                `json:"ancestor_depth,omitempty"`
}

type SessionBindingInfo struct {
	Mode           SessionBindingMode    `json:"mode"`
	AncestorDepth  int                   `json:"ancestor_depth,omitempty"`
	BoundProcess   SessionBindingProcess `json:"bound_process"`
	CreatorProcess SessionBindingProcess `json:"creator_process"`
}

type SessionBindingProcess struct {
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid,omitempty"`
	Name      string `json:"name"`
	Path      string `json:"path"`
}

func DefaultSessionBindingPolicy() SessionBindingPolicy {
	return SessionBindingPolicy{Mode: SessionBindingModeAuto}
}

func NewSessionAncestorBinding(depth int) (SessionBindingPolicy, error) {
	policy := SessionBindingPolicy{Mode: SessionBindingModeAncestor, AncestorDepth: depth}
	return NormalizeSessionBindingPolicy(policy)
}

func NormalizeSessionBindingPolicy(policy SessionBindingPolicy) (SessionBindingPolicy, error) {
	if policy.Mode == "" {
		policy.Mode = SessionBindingModeAuto
	}
	switch policy.Mode {
	case SessionBindingModeAuto:
		if policy.AncestorDepth != 0 {
			return SessionBindingPolicy{}, fmt.Errorf("%w: auto binding does not accept ancestor depth", ErrInvalidSessionBind)
		}
		return policy, nil
	case SessionBindingModeAncestor:
		if policy.AncestorDepth < 1 || policy.AncestorDepth > MaxSessionBindAncestor {
			return SessionBindingPolicy{}, fmt.Errorf(
				"%w: ancestor depth must be between 1 and %d",
				ErrInvalidSessionBind,
				MaxSessionBindAncestor,
			)
		}
		return policy, nil
	default:
		return SessionBindingPolicy{}, fmt.Errorf("%w: unknown binding mode %q", ErrInvalidSessionBind, policy.Mode)
	}
}

func NewSessionCreate(opts SessionCreateOptions) (SessionCreateRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return SessionCreateRequest{}, err
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultSessionTTL
	}
	if ttl < MinRequestTTL || ttl > MaxRequestTTL {
		return SessionCreateRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxRequestTTL)
	}
	maxReads := opts.MaxReads
	if maxReads == 0 {
		maxReads = DefaultSessionMaxReads
	}
	if maxReads < 1 || maxReads > MaxSessionReads {
		return SessionCreateRequest{}, fmt.Errorf("%w: must be between 1 and %d", ErrInvalidSessionRead, MaxSessionReads)
	}
	if err := validatePreparedPath("cwd", opts.CWD, false); err != nil {
		return SessionCreateRequest{}, err
	}
	if err := validatePreparedPath("resolved executable", opts.ResolvedExecutable, true); err != nil {
		return SessionCreateRequest{}, err
	}
	if opts.ExecutableIdentity.IsZero() {
		return SessionCreateRequest{}, fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	command := slices.Clone(opts.Command)
	if len(command) == 0 || command[0] == "" {
		return SessionCreateRequest{}, fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	secrets, err := ParseSecrets(opts.Secrets)
	if err != nil {
		return SessionCreateRequest{}, err
	}
	binding, err := NormalizeSessionBindingPolicy(opts.Binding)
	if err != nil {
		return SessionCreateRequest{}, err
	}
	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}
	return SessionCreateRequest{
		Reason:             reason,
		Command:            command,
		ResolvedExecutable: opts.ResolvedExecutable,
		ExecutableIdentity: opts.ExecutableIdentity,
		CWD:                opts.CWD,
		Secrets:            secrets,
		TTL:                ttl,
		ReceivedAt:         receivedAt,
		ExpiresAt:          expiresAt,
		MaxReads:           maxReads,
		OverrideEnv:        opts.OverrideEnv,
		Binding:            binding,
	}, nil
}

func (r SessionCreateRequest) WithReceiptTime(receivedAt time.Time) SessionCreateRequest {
	r.ReceivedAt = receivedAt
	r.ExpiresAt = receivedAt.Add(r.TTL)
	return r
}

func (r SessionCreateRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r SessionCreateRequest) ValidateForDaemon() error {
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
	if r.MaxReads < 1 || r.MaxReads > MaxSessionReads {
		return fmt.Errorf("%w: must be between 1 and %d", ErrInvalidSessionRead, MaxSessionReads)
	}
	if r.ExecutableIdentity.IsZero() {
		return fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if _, err := NormalizeSessionBindingPolicy(r.Binding); err != nil {
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
	if err := validateDaemonSecrets(r.Secrets); err != nil {
		return err
	}
	return nil
}

func NewSessionResolve(
	sessionToken string,
	command []string,
	resolvedExecutable string,
	executableIdentity fileidentity.Identity,
	cwd string,
	environmentFingerprint string,
) (SessionResolveRequest, error) {
	if err := ValidateSessionToken(sessionToken); err != nil {
		return SessionResolveRequest{}, err
	}
	if len(command) == 0 || command[0] == "" {
		return SessionResolveRequest{}, fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if err := validatePreparedPath("cwd", cwd, false); err != nil {
		return SessionResolveRequest{}, err
	}
	if err := validatePreparedPath("resolved executable", resolvedExecutable, true); err != nil {
		return SessionResolveRequest{}, err
	}
	if executableIdentity.IsZero() {
		return SessionResolveRequest{}, fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if err := validateEnvironmentFingerprint(environmentFingerprint); err != nil {
		return SessionResolveRequest{}, err
	}
	return SessionResolveRequest{
		SessionToken:           sessionToken,
		Command:                slices.Clone(command),
		ResolvedExecutable:     resolvedExecutable,
		ExecutableIdentity:     executableIdentity,
		CWD:                    cwd,
		EnvironmentFingerprint: environmentFingerprint,
	}, nil
}

func (r SessionResolveRequest) WithExpectedPeer(expected peercred.Expected) SessionResolveRequest {
	r.ExpectedPeer = expected
	return r
}

func (r SessionResolveRequest) WithRequestedAliases(aliases []string) (SessionResolveRequest, error) {
	normalized, err := NormalizeAliases(aliases)
	if err != nil {
		return SessionResolveRequest{}, err
	}
	r.RequestedAliases = normalized
	return r, nil
}

func (r SessionResolveRequest) ValidateForDaemon() error {
	if err := ValidateSessionToken(r.SessionToken); err != nil {
		return err
	}
	if len(r.Command) == 0 || r.Command[0] == "" {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if err := validateEnvironmentFingerprint(r.EnvironmentFingerprint); err != nil {
		return err
	}
	if err := validateNormalizedAliases(r.RequestedAliases); err != nil {
		return err
	}
	if err := validateDaemonPreparedPath("cwd", r.CWD, false); err != nil {
		return err
	}
	if err := validateDaemonPreparedPath("resolved executable", r.ResolvedExecutable, true); err != nil {
		return err
	}
	if r.ExecutableIdentity.IsZero() {
		return fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	if err := fileidentity.Verify(r.ResolvedExecutable, r.ExecutableIdentity); err != nil {
		return fmt.Errorf("%w: executable identity changed: %w", ErrInvalidRequest, err)
	}
	if r.ExpectedPeer.UID < 0 || r.ExpectedPeer.GID < 0 || r.ExpectedPeer.PID <= 0 ||
		r.ExpectedPeer.ExecutablePath == "" || r.ExpectedPeer.CWD == "" {
		return fmt.Errorf("%w: expected peer metadata is required", ErrInvalidRequest)
	}
	return nil
}

func NewSessionDestroy(sessionID string) (SessionDestroyRequest, error) {
	req := SessionDestroyRequest{SessionID: sessionID}
	if err := req.ValidateForDaemon(); err != nil {
		return SessionDestroyRequest{}, err
	}
	return req, nil
}

func NewSessionDestroyAll() SessionDestroyRequest {
	return SessionDestroyRequest{All: true}
}

func (r SessionDestroyRequest) ValidateForDaemon() error {
	if r.All {
		if r.SessionID != "" {
			return fmt.Errorf("%w: --all cannot be combined with a session id", ErrInvalidRequest)
		}
		return nil
	}
	return ValidateSessionID(r.SessionID)
}

func ValidateSessionID(sessionID string) error {
	if !sessionIDPattern.MatchString(sessionID) {
		return fmt.Errorf("%w: %q", ErrInvalidSessionID, sessionID)
	}
	return nil
}

func ValidateSessionToken(sessionToken string) error {
	if !sessionTokenPattern.MatchString(sessionToken) {
		return fmt.Errorf("%w: %q", ErrInvalidSessionToken, sessionToken)
	}
	return nil
}

func NormalizeAliases(aliases []string) ([]string, error) {
	if len(aliases) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(aliases))
	normalized := make([]string, 0, len(aliases))
	for _, raw := range aliases {
		alias := strings.TrimSpace(raw)
		if !aliasPattern.MatchString(alias) {
			return nil, fmt.Errorf("%w: alias must match [A-Z_][A-Z0-9_]*, for example API_TOKEN (got: %q)", ErrInvalidAlias, raw)
		}
		if _, ok := seen[alias]; ok {
			return nil, fmt.Errorf("%w: duplicate alias %q", ErrInvalidAlias, alias)
		}
		seen[alias] = struct{}{}
		normalized = append(normalized, alias)
	}
	slices.Sort(normalized)
	return normalized, nil
}

func validateNormalizedAliases(aliases []string) error {
	normalized, err := NormalizeAliases(aliases)
	if err != nil {
		return err
	}
	if !slices.Equal(aliases, normalized) {
		return fmt.Errorf("%w: aliases must be sorted and trimmed", ErrInvalidAlias)
	}
	return nil
}
