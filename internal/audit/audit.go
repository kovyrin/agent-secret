package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrClosed            = errors.New("audit writer closed")
	ErrInsecureAuditLog  = errors.New("insecure audit log permissions")
	ErrInvalidAuditEvent = errors.New("invalid audit event")
)

type EventType string

const (
	EventApprovalRequested                  EventType = "approval_requested"
	EventApprovalGranted                    EventType = "approval_granted"
	EventApprovalDenied                     EventType = "approval_denied"
	EventApprovalTimedOut                   EventType = "approval_timed_out"
	EventApprovalReused                     EventType = "approval_reused"
	EventApprovalRefreshed                  EventType = "approval_refreshed"
	EventSecretFetchStarted                 EventType = "secret_fetch_started"
	EventSecretFetchFailed                  EventType = "secret_fetch_failed"
	EventCommandStarting                    EventType = "command_starting"
	EventCommandStarted                     EventType = "command_started"
	EventCommandCompleted                   EventType = "command_completed"
	EventExecClientDisconnectedAfterPayload EventType = "exec_client_disconnected_after_payload"
	EventExecClientDisconnectedAfterStart   EventType = "exec_client_disconnected_after_start"
	EventDaemonStop                         EventType = "daemon_stop"
)

type SecretRef struct {
	Alias   string `json:"alias"`
	Ref     string `json:"ref"`
	Account string `json:"account,omitempty"`
}

type Event struct {
	Timestamp              time.Time   `json:"timestamp"`
	Type                   EventType   `json:"type"`
	RequestID              string      `json:"request_id,omitempty"`
	ApprovalID             string      `json:"approval_id,omitempty"`
	Reason                 string      `json:"reason,omitempty"`
	Command                []string    `json:"command,omitempty"`
	ResolvedExecutable     string      `json:"resolved_executable,omitempty"`
	CWD                    string      `json:"cwd,omitempty"`
	SecretRefs             []SecretRef `json:"secret_refs,omitempty"`
	ChildPID               *int        `json:"child_pid,omitempty"`
	ExitCode               *int        `json:"exit_code,omitempty"`
	Signal                 string      `json:"signal,omitempty"`
	ErrorCode              string      `json:"error_code,omitempty"`
	RequesterPID           *int        `json:"requester_pid,omitempty"`
	RequesterUID           *int        `json:"requester_uid,omitempty"`
	RequesterPath          string      `json:"requester_path,omitempty"`
	RemainingTTLMillis     *int64      `json:"remaining_ttl_ms,omitempty"`
	RemainingUses          *int        `json:"remaining_uses,omitempty"`
	ForceRefresh           bool        `json:"force_refresh,omitempty"`
	OverrideEnv            bool        `json:"override_env,omitempty"`
	OverriddenAliases      []string    `json:"overridden_aliases,omitempty"`
	AllowMutableExecutable bool        `json:"allow_mutable_executable,omitempty"`
}

type Writer struct {
	mu   sync.Mutex
	now  func() time.Time
	file *os.File
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, "Library", "Logs", "agent-secret", "audit.jsonl"), nil
}

func OpenDefault(now func() time.Time) (*Writer, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	return openPath(path, now)
}

func FromExecRequest(eventType EventType, requestID string, req request.ExecRequest) Event {
	return Event{
		Type:                   eventType,
		RequestID:              requestID,
		Reason:                 req.Reason,
		Command:                slices.Clone(req.Command),
		ResolvedExecutable:     req.ResolvedExecutable,
		CWD:                    req.CWD,
		SecretRefs:             secretRefs(req.Secrets),
		ForceRefresh:           req.ForceRefresh,
		OverrideEnv:            req.OverrideEnv,
		OverriddenAliases:      slices.Clone(req.OverriddenAliases),
		AllowMutableExecutable: req.AllowMutableExecutable,
	}
}

func (w *Writer) ApprovalReused(ctx context.Context, event policy.ReuseAuditEvent) error {
	remainingTTL := event.RemainingTTL.Milliseconds()
	remainingUses := event.RemainingUse
	return w.Record(ctx, Event{
		Type:               EventApprovalReused,
		ApprovalID:         event.ApprovalID,
		RemainingTTLMillis: &remainingTTL,
		RemainingUses:      &remainingUses,
	})
}

func (w *Writer) Preflight(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return ErrClosed
	}
	return nil
}

func (w *Writer) Record(ctx context.Context, event Event) error {
	if event.Type == "" {
		return ErrInvalidAuditEvent
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return ErrClosed
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = w.now().UTC()
	}
	if err := json.NewEncoder(w.file).Encode(event); err != nil {
		return fmt.Errorf("write audit event %s: %w", event.Type, err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("sync audit event %s: %w", event.Type, err)
	}
	return nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func openPath(path string, now func() time.Time) (*Writer, error) {
	if now == nil {
		now = time.Now
	}
	dir := filepath.Dir(path)
	if err := prepareAuditDirectory(dir); err != nil {
		return nil, err
	}
	if err := rejectInsecureFile(path); err != nil {
		return nil, err
	}
	if err := rejectAuditDirectoryAncestry(dir); err != nil {
		return nil, err
	}

	file, err := openAuditLog(path)
	if err != nil {
		return nil, err
	}

	return &Writer{now: now, file: file}, nil
}

func prepareAuditDirectory(dir string) error {
	if err := rejectAuditDirectoryAncestry(dir); err != nil {
		return err
	}
	_, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create audit directory: %w", err)
		}
		return rejectInsecureDirectory(dir)
	}
	if err != nil {
		return fmt.Errorf("stat audit directory: %w", err)
	}
	return rejectInsecureDirectory(dir)
}

func rejectInsecureDirectory(dir string) error {
	if err := rejectAuditDirectoryAncestry(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat audit directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecureAuditLog, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecureAuditLog, dir)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureAuditLog, dir, info.Mode().Perm())
	}
	if uid, ok := fileOwnerUID(info); ok && uid != os.Getuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrInsecureAuditLog, dir, uid)
	}
	return nil
}

func rejectAuditDirectoryAncestry(dir string) error {
	cleanDir := filepath.Clean(dir)
	for current := cleanDir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat audit directory ancestor: %w", err)
		}
		if err == nil {
			if err := rejectAuditDirectoryAncestorInfo(cleanDir, current, info); err != nil {
				return err
			}
		}

		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func rejectAuditDirectoryAncestorInfo(cleanDir, current string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		if isAllowedAuditRootAlias(current) {
			return nil
		}
		return fmt.Errorf("%w: %s contains symlink ancestor %s", ErrInsecureAuditLog, cleanDir, current)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s contains non-directory ancestor %s", ErrInsecureAuditLog, cleanDir, current)
	}
	return nil
}

func isAllowedAuditRootAlias(path string) bool {
	switch path {
	case "/etc", "/tmp", "/var":
		return true
	default:
		return false
	}
}

func rejectInsecureFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecureAuditLog, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecureAuditLog, path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureAuditLog, path, info.Mode().Perm())
	}
	if uid, ok := fileOwnerUID(info); ok && uid != os.Getuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrInsecureAuditLog, path, uid)
	}
	return nil
}

func openAuditLog(path string) (*os.File, error) {
	//nolint:gosec // G304: audit path is fixed under the user's home; O_NOFOLLOW and fstat checks bind it to a regular owner-private file.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := rejectInsecureOpenFile(file, path); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func rejectInsecureOpenFile(file *os.File, path string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat open audit log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecureAuditLog, path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureAuditLog, path, info.Mode().Perm())
	}
	if uid, ok := fileOwnerUID(info); ok && uid != os.Getuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrInsecureAuditLog, path, uid)
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}

func secretRefs(secrets []request.Secret) []SecretRef {
	refs := make([]SecretRef, 0, len(secrets))
	for _, secret := range secrets {
		refs = append(refs, SecretRef{Alias: secret.Alias, Ref: secret.Ref.Raw, Account: secret.Account})
	}
	return refs
}
