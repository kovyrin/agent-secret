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
	EventApprovalReused                     EventType = "approval_reused"
	EventApprovalRefreshed                  EventType = "approval_refreshed"
	EventCommandStarting                    EventType = "command_starting"
	EventCommandStarted                     EventType = "command_started"
	EventCommandCompleted                   EventType = "command_completed"
	EventExecClientDisconnectedAfterPayload EventType = "exec_client_disconnected_after_payload"
	EventDaemonStop                         EventType = "daemon_stop"
)

type SecretRef struct {
	Alias string `json:"alias"`
	Ref   string `json:"ref"`
}

type Event struct {
	Timestamp          time.Time            `json:"timestamp"`
	Type               EventType            `json:"type"`
	RequestID          string               `json:"request_id,omitempty"`
	ApprovalID         string               `json:"approval_id,omitempty"`
	SessionID          string               `json:"session_id,omitempty"`
	Reason             string               `json:"reason,omitempty"`
	Command            []string             `json:"command,omitempty"`
	ResolvedExecutable string               `json:"resolved_executable,omitempty"`
	CWD                string               `json:"cwd,omitempty"`
	DeliveryMode       request.DeliveryMode `json:"delivery_mode,omitempty"`
	SecretRefs         []SecretRef          `json:"secret_refs,omitempty"`
	ChildPID           *int                 `json:"child_pid,omitempty"`
	ExitCode           *int                 `json:"exit_code,omitempty"`
	Signal             string               `json:"signal,omitempty"`
	ErrorCode          string               `json:"error_code,omitempty"`
	RemainingTTLMillis *int64               `json:"remaining_ttl_ms,omitempty"`
	RemainingUses      *int                 `json:"remaining_uses,omitempty"`
	ForceRefresh       bool                 `json:"force_refresh,omitempty"`
	OverrideEnv        bool                 `json:"override_env,omitempty"`
	OverriddenAliases  []string             `json:"overridden_aliases,omitempty"`
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
		Type:               eventType,
		RequestID:          requestID,
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		ResolvedExecutable: req.ResolvedExecutable,
		CWD:                req.CWD,
		DeliveryMode:       req.DeliveryMode,
		SecretRefs:         secretRefs(req.Secrets),
		ForceRefresh:       req.ForceRefresh,
		OverrideEnv:        req.OverrideEnv,
		OverriddenAliases:  slices.Clone(req.OverriddenAliases),
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("secure audit directory: %w", err)
	}
	if err := rejectInsecureFile(path); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := rejectInsecureFile(path); err != nil {
		_ = file.Close()
		return nil, err
	}

	return &Writer{now: now, file: file}, nil
}

func rejectInsecureFile(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%w: %s is a directory", ErrInsecureAuditLog, path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureAuditLog, path, info.Mode().Perm())
	}
	return nil
}

func secretRefs(secrets []request.Secret) []SecretRef {
	refs := make([]SecretRef, 0, len(secrets))
	for _, secret := range secrets {
		refs = append(refs, SecretRef{Alias: secret.Alias, Ref: secret.Ref.Raw})
	}
	return refs
}
