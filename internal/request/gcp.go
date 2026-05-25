package request

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

const (
	DefaultGCPSessionTTL              = 30 * time.Minute
	MaxGCPSessionTTL                  = time.Hour
	DefaultGCPSessionMaxCommandStarts = 20
	MaxGCPSessionMaxCommandStarts     = 100
)

const (
	GCPDeliveryModeTokenFile = "token_file"
)

var (
	ErrInvalidGCPAccount          = errors.New("invalid GCP bootstrap account")
	ErrInvalidGCPProject          = errors.New("invalid GCP project")
	ErrInvalidGCPServiceAccount   = errors.New("invalid GCP service account")
	ErrInvalidGCPScope            = errors.New("invalid GCP OAuth scope")
	ErrInvalidGCPSession          = errors.New("invalid GCP session")
	ErrInvalidGCPSessionMaxStarts = errors.New("invalid GCP session max command starts")
)

type GCPAccess struct {
	GoogleAccount  string   `json:"google_account"`
	Project        string   `json:"project"`
	ServiceAccount string   `json:"service_account"`
	Scopes         []string `json:"scopes"`
}

type GCPExecOptions struct {
	Reason                 string
	Command                []string
	ResolvedExecutable     string
	ExecutableIdentity     fileidentity.Identity
	CWD                    string
	EnvironmentFingerprint string
	Access                 GCPAccess
	ProfileName            string
	ConfigRoot             string
	TTL                    time.Duration
	ReceivedAt             time.Time
	ReuseOnly              bool
}

type GCPExecRequest struct {
	Reason                 string                `json:"reason"`
	Command                []string              `json:"command"`
	ResolvedExecutable     string                `json:"resolved_executable"`
	ExecutableIdentity     fileidentity.Identity `json:"executable_identity"`
	CWD                    string                `json:"cwd"`
	EnvironmentFingerprint string                `json:"environment_fingerprint"`
	GoogleAccount          string                `json:"google_account"`
	Project                string                `json:"project"`
	ServiceAccount         string                `json:"service_account"`
	Scopes                 []string              `json:"scopes"`
	ProfileName            string                `json:"profile_name,omitempty"`
	ConfigRoot             string                `json:"config_root,omitempty"`
	DeliveryMode           string                `json:"delivery_mode"`
	TTL                    time.Duration         `json:"ttl"`
	ReceivedAt             time.Time             `json:"received_at"`
	ExpiresAt              time.Time             `json:"expires_at"`
	ReuseOnly              bool                  `json:"reuse_only,omitempty"`
}

type GCPSessionCreateOptions struct {
	Reason           string
	Access           GCPAccess
	ProfileName      string
	ConfigSourcePath string
	ProjectRoot      string
	TTL              time.Duration
	MaxCommandStarts int
	ReceivedAt       time.Time
}

type GCPSessionCreateRequest struct {
	Reason           string        `json:"reason"`
	GoogleAccount    string        `json:"google_account"`
	Project          string        `json:"project"`
	ServiceAccount   string        `json:"service_account"`
	Scopes           []string      `json:"scopes"`
	ProfileName      string        `json:"profile_name"`
	ConfigSourcePath string        `json:"config_source_path"`
	ProjectRoot      string        `json:"project_root"`
	DeliveryMode     string        `json:"delivery_mode"`
	TTL              time.Duration `json:"ttl"`
	ReceivedAt       time.Time     `json:"received_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	MaxCommandStarts int           `json:"max_command_starts"`
}

type GCPSessionUseOptions struct {
	SessionHandle          string
	Command                []string
	ResolvedExecutable     string
	ExecutableIdentity     fileidentity.Identity
	CWD                    string
	EnvironmentFingerprint string
}

type GCPSessionUseRequest struct {
	SessionHandle          string                `json:"session_handle"`
	Command                []string              `json:"command"`
	ResolvedExecutable     string                `json:"resolved_executable"`
	ExecutableIdentity     fileidentity.Identity `json:"executable_identity"`
	CWD                    string                `json:"cwd"`
	EnvironmentFingerprint string                `json:"environment_fingerprint"`
}

type GCPSessionDestroyRequest struct {
	SessionHandle string `json:"session_handle"`
	CWD           string `json:"cwd"`
}

func NewGCPExec(opts GCPExecOptions) (GCPExecRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return GCPExecRequest{}, err
	}
	access, err := NormalizeGCPAccess(opts.Access)
	if err != nil {
		return GCPExecRequest{}, err
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultExecTTL
	}
	if ttl < MinRequestTTL || ttl > MaxRequestTTL {
		return GCPExecRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxRequestTTL)
	}
	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}
	if err := validateCommandSnapshot(opts.Command, opts.CWD, opts.ResolvedExecutable, opts.ExecutableIdentity, opts.EnvironmentFingerprint); err != nil {
		return GCPExecRequest{}, err
	}
	configRoot, err := normalizeOptionalPreparedDir("config root", opts.ConfigRoot)
	if err != nil {
		return GCPExecRequest{}, err
	}
	return GCPExecRequest{
		Reason:                 reason,
		Command:                slices.Clone(opts.Command),
		ResolvedExecutable:     opts.ResolvedExecutable,
		ExecutableIdentity:     opts.ExecutableIdentity,
		CWD:                    opts.CWD,
		EnvironmentFingerprint: opts.EnvironmentFingerprint,
		GoogleAccount:          access.GoogleAccount,
		Project:                access.Project,
		ServiceAccount:         access.ServiceAccount,
		Scopes:                 slices.Clone(access.Scopes),
		ProfileName:            strings.TrimSpace(opts.ProfileName),
		ConfigRoot:             configRoot,
		DeliveryMode:           GCPDeliveryModeTokenFile,
		TTL:                    ttl,
		ReceivedAt:             receivedAt,
		ExpiresAt:              expiresAt,
		ReuseOnly:              opts.ReuseOnly,
	}, nil
}

func (r GCPExecRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r GCPExecRequest) WithReceiptTime(receivedAt time.Time) GCPExecRequest {
	r.ReceivedAt = receivedAt
	r.ExpiresAt = receivedAt.Add(r.TTL)
	return r
}

func (r GCPExecRequest) Access() GCPAccess {
	return GCPAccess{
		GoogleAccount:  r.GoogleAccount,
		Project:        r.Project,
		ServiceAccount: r.ServiceAccount,
		Scopes:         slices.Clone(r.Scopes),
	}
}

func (r GCPExecRequest) ValidateForDaemon() error {
	if err := validateGCPLifecycle(daemonGCPLifecycle{
		Reason:             r.Reason,
		Command:            r.Command,
		CWD:                r.CWD,
		ResolvedExecutable: r.ResolvedExecutable,
		TTL:                r.TTL,
		ReceivedAt:         r.ReceivedAt,
		ExpiresAt:          r.ExpiresAt,
		MinTTL:             MinRequestTTL,
		MaxTTL:             MaxRequestTTL,
	}); err != nil {
		return err
	}
	if err := validateCommandSnapshot(r.Command, r.CWD, r.ResolvedExecutable, r.ExecutableIdentity, r.EnvironmentFingerprint); err != nil {
		return err
	}
	access, err := NormalizeGCPAccess(r.Access())
	if err != nil {
		return err
	}
	if access.GoogleAccount != r.GoogleAccount ||
		access.Project != r.Project ||
		access.ServiceAccount != r.ServiceAccount ||
		!slices.Equal(access.Scopes, r.Scopes) {
		return fmt.Errorf("%w: GCP access fields must be pre-normalized", ErrInvalidRequest)
	}
	if r.DeliveryMode != GCPDeliveryModeTokenFile {
		return fmt.Errorf("%w: unsupported GCP delivery mode %q", ErrInvalidRequest, r.DeliveryMode)
	}
	if _, err := normalizeOptionalPreparedDir("config root", r.ConfigRoot); err != nil {
		return err
	}
	return nil
}

func NewGCPSessionCreate(opts GCPSessionCreateOptions) (GCPSessionCreateRequest, error) {
	reason, err := validateReason(opts.Reason)
	if err != nil {
		return GCPSessionCreateRequest{}, err
	}
	access, err := NormalizeGCPAccess(opts.Access)
	if err != nil {
		return GCPSessionCreateRequest{}, err
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = DefaultGCPSessionTTL
	}
	if ttl < MinRequestTTL || ttl > MaxGCPSessionTTL {
		return GCPSessionCreateRequest{}, fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, MinRequestTTL, MaxGCPSessionTTL)
	}
	maxStarts := opts.MaxCommandStarts
	if maxStarts == 0 {
		maxStarts = DefaultGCPSessionMaxCommandStarts
	}
	if err := validateGCPSessionMaxCommandStarts(maxStarts); err != nil {
		return GCPSessionCreateRequest{}, err
	}
	profileName := strings.TrimSpace(opts.ProfileName)
	if profileName == "" {
		return GCPSessionCreateRequest{}, fmt.Errorf("%w: profile name is required", ErrInvalidGCPSession)
	}
	sourcePath, err := normalizePreparedFile("config source path", opts.ConfigSourcePath)
	if err != nil {
		return GCPSessionCreateRequest{}, err
	}
	projectRoot, err := normalizePreparedDir("project root", opts.ProjectRoot)
	if err != nil {
		return GCPSessionCreateRequest{}, err
	}
	receivedAt := opts.ReceivedAt
	expiresAt := time.Time{}
	if !receivedAt.IsZero() {
		expiresAt = receivedAt.Add(ttl)
	}
	return GCPSessionCreateRequest{
		Reason:           reason,
		GoogleAccount:    access.GoogleAccount,
		Project:          access.Project,
		ServiceAccount:   access.ServiceAccount,
		Scopes:           slices.Clone(access.Scopes),
		ProfileName:      profileName,
		ConfigSourcePath: sourcePath,
		ProjectRoot:      projectRoot,
		DeliveryMode:     GCPDeliveryModeTokenFile,
		TTL:              ttl,
		ReceivedAt:       receivedAt,
		ExpiresAt:        expiresAt,
		MaxCommandStarts: maxStarts,
	}, nil
}

func (r GCPSessionCreateRequest) Expired(at time.Time) bool {
	return !at.Before(r.ExpiresAt)
}

func (r GCPSessionCreateRequest) WithReceiptTime(receivedAt time.Time) GCPSessionCreateRequest {
	r.ReceivedAt = receivedAt
	r.ExpiresAt = receivedAt.Add(r.TTL)
	return r
}

func (r GCPSessionCreateRequest) Access() GCPAccess {
	return GCPAccess{
		GoogleAccount:  r.GoogleAccount,
		Project:        r.Project,
		ServiceAccount: r.ServiceAccount,
		Scopes:         slices.Clone(r.Scopes),
	}
}

func (r GCPSessionCreateRequest) ValidateForDaemon() error {
	if err := validateGCPLifecycle(daemonGCPLifecycle{
		Reason:     r.Reason,
		TTL:        r.TTL,
		ReceivedAt: r.ReceivedAt,
		ExpiresAt:  r.ExpiresAt,
		MinTTL:     MinRequestTTL,
		MaxTTL:     MaxGCPSessionTTL,
	}); err != nil {
		return err
	}
	if err := validateGCPSessionMaxCommandStarts(r.MaxCommandStarts); err != nil {
		return err
	}
	if _, err := NormalizeGCPAccess(r.Access()); err != nil {
		return err
	}
	if strings.TrimSpace(r.ProfileName) != r.ProfileName || r.ProfileName == "" {
		return fmt.Errorf("%w: profile name must be pre-normalized", ErrInvalidGCPSession)
	}
	if _, err := normalizePreparedFile("config source path", r.ConfigSourcePath); err != nil {
		return err
	}
	if _, err := normalizePreparedDir("project root", r.ProjectRoot); err != nil {
		return err
	}
	if r.DeliveryMode != GCPDeliveryModeTokenFile {
		return fmt.Errorf("%w: unsupported GCP delivery mode %q", ErrInvalidRequest, r.DeliveryMode)
	}
	return nil
}

func NewGCPSessionUse(opts GCPSessionUseOptions) (GCPSessionUseRequest, error) {
	handle := strings.TrimSpace(opts.SessionHandle)
	if handle == "" {
		return GCPSessionUseRequest{}, fmt.Errorf("%w: session handle is required", ErrInvalidGCPSession)
	}
	if err := validateCommandSnapshot(opts.Command, opts.CWD, opts.ResolvedExecutable, opts.ExecutableIdentity, opts.EnvironmentFingerprint); err != nil {
		return GCPSessionUseRequest{}, err
	}
	return GCPSessionUseRequest{
		SessionHandle:          handle,
		Command:                slices.Clone(opts.Command),
		ResolvedExecutable:     opts.ResolvedExecutable,
		ExecutableIdentity:     opts.ExecutableIdentity,
		CWD:                    opts.CWD,
		EnvironmentFingerprint: opts.EnvironmentFingerprint,
	}, nil
}

func (r GCPSessionUseRequest) ValidateForDaemon() error {
	if strings.TrimSpace(r.SessionHandle) != r.SessionHandle || r.SessionHandle == "" {
		return fmt.Errorf("%w: session handle must be pre-normalized", ErrInvalidGCPSession)
	}
	return validateCommandSnapshot(r.Command, r.CWD, r.ResolvedExecutable, r.ExecutableIdentity, r.EnvironmentFingerprint)
}

func NewGCPSessionDestroy(handle string, cwd string) (GCPSessionDestroyRequest, error) {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return GCPSessionDestroyRequest{}, fmt.Errorf("%w: session handle is required", ErrInvalidGCPSession)
	}
	normalizedCWD, err := normalizeOptionalPreparedDir("cwd", cwd)
	if err != nil {
		return GCPSessionDestroyRequest{}, err
	}
	return GCPSessionDestroyRequest{SessionHandle: handle, CWD: normalizedCWD}, nil
}

func (r GCPSessionDestroyRequest) ValidateForDaemon() error {
	if strings.TrimSpace(r.SessionHandle) != r.SessionHandle || r.SessionHandle == "" {
		return fmt.Errorf("%w: session handle must be pre-normalized", ErrInvalidGCPSession)
	}
	_, err := normalizeOptionalPreparedDir("cwd", r.CWD)
	return err
}

func NormalizeGCPAccess(access GCPAccess) (GCPAccess, error) {
	googleAccount := strings.TrimSpace(access.GoogleAccount)
	if googleAccount == "" {
		return GCPAccess{}, fmt.Errorf("%w: google_account is required", ErrInvalidGCPAccount)
	}
	project := strings.TrimSpace(access.Project)
	if project == "" {
		return GCPAccess{}, fmt.Errorf("%w: project is required", ErrInvalidGCPProject)
	}
	serviceAccount := strings.TrimSpace(access.ServiceAccount)
	if serviceAccount == "" || !strings.Contains(serviceAccount, "@") {
		return GCPAccess{}, fmt.Errorf("%w: service_account must be an email address", ErrInvalidGCPServiceAccount)
	}
	scopes, err := NormalizeGCPOAuthScopes(access.Scopes)
	if err != nil {
		return GCPAccess{}, err
	}
	return GCPAccess{
		GoogleAccount:  googleAccount,
		Project:        project,
		ServiceAccount: serviceAccount,
		Scopes:         scopes,
	}, nil
}

func NormalizeGCPOAuthScopes(scopes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		parsed, err := url.Parse(scope)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, fmt.Errorf("%w: scope must be an https URL (got %q)", ErrInvalidGCPScope, scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	slices.Sort(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: at least one scope is required", ErrInvalidGCPScope)
	}
	return out, nil
}

func GCPSessionHandleAuditID(handle string) string {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(handle))
	prefix := handle
	if len(prefix) > 10 {
		prefix = prefix[:10]
	}
	return prefix + ":" + hex.EncodeToString(sum[:])[:16]
}

func GCPSessionRemainingTokenRefreshMargin(lifetime time.Duration) time.Duration {
	percent := lifetime / 5
	if percent < time.Minute {
		return time.Minute
	}
	return percent
}

type daemonGCPLifecycle struct {
	Reason             string
	Command            []string
	CWD                string
	ResolvedExecutable string
	TTL                time.Duration
	ReceivedAt         time.Time
	ExpiresAt          time.Time
	MinTTL             time.Duration
	MaxTTL             time.Duration
}

func validateGCPLifecycle(lifecycle daemonGCPLifecycle) error {
	reason, err := validateReason(lifecycle.Reason)
	if err != nil {
		return err
	}
	if reason != lifecycle.Reason {
		return fmt.Errorf("%w: reason must be pre-normalized", ErrInvalidReason)
	}
	if lifecycle.TTL < lifecycle.MinTTL || lifecycle.TTL > lifecycle.MaxTTL {
		return fmt.Errorf("%w: must be between %s and %s", ErrInvalidTTL, lifecycle.MinTTL, lifecycle.MaxTTL)
	}
	if lifecycle.ReceivedAt.IsZero() || lifecycle.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: request times are required", ErrInvalidRequest)
	}
	if !lifecycle.ExpiresAt.Equal(lifecycle.ReceivedAt.Add(lifecycle.TTL)) {
		return fmt.Errorf("%w: expires_at must equal received_at plus ttl", ErrInvalidTTL)
	}
	if lifecycle.CWD != "" {
		if err := validatePreparedPath("cwd", lifecycle.CWD, false); err != nil {
			return err
		}
	}
	if lifecycle.ResolvedExecutable != "" {
		if err := validatePreparedPath("resolved executable", lifecycle.ResolvedExecutable, true); err != nil {
			return err
		}
	}
	if lifecycle.Command != nil && (len(lifecycle.Command) == 0 || lifecycle.Command[0] == "") {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	return nil
}

func validateCommandSnapshot(
	command []string,
	cwd string,
	resolvedExecutable string,
	executableIdentity fileidentity.Identity,
	environmentFingerprint string,
) error {
	if len(command) == 0 || command[0] == "" {
		return fmt.Errorf("%w: argv is required", ErrInvalidCommand)
	}
	if err := validatePreparedPath("cwd", cwd, false); err != nil {
		return err
	}
	if err := validatePreparedPath("resolved executable", resolvedExecutable, true); err != nil {
		return err
	}
	if executableIdentity.IsZero() {
		return fmt.Errorf("%w: executable identity is required", ErrInvalidRequest)
	}
	return validateEnvironmentFingerprint(environmentFingerprint)
}

func validateGCPSessionMaxCommandStarts(maxStarts int) error {
	if maxStarts < 1 || maxStarts > MaxGCPSessionMaxCommandStarts {
		return fmt.Errorf("%w: must be between 1 and %d", ErrInvalidGCPSessionMaxStarts, MaxGCPSessionMaxCommandStarts)
	}
	return nil
}

func normalizePreparedDir(name string, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidRequest, name)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%w: %s must be an absolute normalized path", ErrInvalidRequest, name)
	}
	return path, nil
}

func normalizePreparedFile(name string, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidRequest, name)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasSuffix(path, "/") {
		return "", fmt.Errorf("%w: %s must be an absolute normalized file path", ErrInvalidRequest, name)
	}
	return path, nil
}

func normalizeOptionalPreparedDir(name string, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	return normalizePreparedDir(name, path)
}
