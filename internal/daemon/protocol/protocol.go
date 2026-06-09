package protocol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
)

const ProtocolVersion = 1
const DefaultMaxProtocolFrameBytes int64 = 1 << 20

type MessageType string

const (
	TypeHelperHello       MessageType = "helper.hello"
	TypeDaemonStatus      MessageType = "daemon.status"
	TypeDaemonStop        MessageType = "daemon.stop"
	TypeOnePasswordStatus MessageType = "onepassword.status"
	TypeApprovalPending   MessageType = "approval.pending"
	TypeApprovalDecision  MessageType = "approval.decision"
	TypeRequestExec       MessageType = "request.exec"
	TypeItemDescribe      MessageType = "item.describe"
	TypeSessionCreate     MessageType = "session.create"
	TypeSessionResolve    MessageType = "session.resolve"
	TypeSessionDestroy    MessageType = "session.destroy"
	TypeSessionList       MessageType = "session.list"
	TypeCommandStarted    MessageType = "command.started"
	TypeCommandCompleted  MessageType = "command.completed"
	TypeOK                MessageType = "ok"
	TypeError             MessageType = "error"
)

type ErrorCode string

const (
	ErrorCodeApprovalDenied           ErrorCode = "approval_denied"
	ErrorCodeApprovalUnavailable      ErrorCode = "approval_unavailable"
	ErrorCodeApproverIdentityMismatch ErrorCode = "approver_identity_mismatch"
	ErrorCodeApproverPeerMismatch     ErrorCode = "approver_peer_mismatch"
	ErrorCodeAuditFailed              ErrorCode = "audit_failed"
	ErrorCodeBadApprovalDecision      ErrorCode = "bad_approval_decision"
	ErrorCodeBadCommandCompleted      ErrorCode = "bad_command_completed"
	ErrorCodeBadCommandStarted        ErrorCode = "bad_command_started"
	ErrorCodeBadEnvelope              ErrorCode = "bad_envelope"
	ErrorCodeBadRequest               ErrorCode = "bad_request"
	ErrorCodeBadType                  ErrorCode = "bad_type"
	ErrorCodeContextCanceled          ErrorCode = "context_canceled"
	ErrorCodeContextDeadlineExceeded  ErrorCode = "context_deadline_exceeded"
	ErrorCodeDaemonStopped            ErrorCode = "daemon_stopped"
	ErrorCodeFrameTooLarge            ErrorCode = "frame_too_large"
	ErrorCodeInvalidNonce             ErrorCode = "invalid_nonce"
	ErrorCodeNoPendingApproval        ErrorCode = "no_pending_approval"
	ErrorCodeNoReusableApproval       ErrorCode = "no_reusable_approval"
	ErrorCodePeerRejected             ErrorCode = "peer_rejected"
	ErrorCodeRequestActive            ErrorCode = "request_active"
	ErrorCodeRequestExpired           ErrorCode = "request_expired"
	ErrorCodeRequestFailed            ErrorCode = "request_failed"
	ErrorCodeResolveFailed            ErrorCode = "resolve_failed"
	ErrorCodeSessionNotFound          ErrorCode = "session_not_found"
	ErrorCodeSessionPeerMismatch      ErrorCode = "session_peer_mismatch"
	ErrorCodeSessionReadExhausted     ErrorCode = "session_read_exhausted"
	ErrorCodeStaleApproval            ErrorCode = "stale_approval"
	ErrorCodeUntrustedClient          ErrorCode = "untrusted_client"
)

var (
	ErrInvalidNonce      = errors.New("invalid request nonce")
	ErrMalformedEnvelope = errors.New("malformed protocol envelope")
	ErrProtocolFrameSize = errors.New("protocol frame exceeds maximum size")
	ErrProtocolVersion   = errors.New("unsupported protocol version")
	ErrProtocolType      = errors.New("unsupported protocol message type")
)

type Envelope struct {
	Version   int             `json:"version"`
	Type      MessageType     `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Nonce     string          `json:"nonce,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Correlation struct {
	RequestID string
	Nonce     string
}

func (e Envelope) Correlation() Correlation {
	return Correlation{RequestID: e.RequestID, Nonce: e.Nonce}
}

type ErrorPayload struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

type ExecResponsePayload struct {
	Env           map[string]string `json:"env"`
	SecretAliases []string          `json:"secret_aliases"`
}

type SessionCreateResponsePayload struct {
	SessionID      string    `json:"session_id"`
	SecretAliases  []string  `json:"secret_aliases"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxReads       int       `json:"max_reads"`
	RemainingReads int       `json:"remaining_reads"`
}

type SessionResolveResponsePayload struct {
	Env           map[string]string `json:"env"`
	SecretAliases []string          `json:"secret_aliases"`
	OverrideEnv   bool              `json:"override_env"`
}

type SessionDestroyResponsePayload struct {
	SessionID string `json:"session_id"`
	Destroyed bool   `json:"destroyed"`
}

type SessionListResponsePayload struct {
	Sessions []SessionInfoPayload `json:"sessions"`
}

type SessionInfoPayload struct {
	SessionID      string    `json:"session_id"`
	Reason         string    `json:"reason"`
	CWD            string    `json:"cwd"`
	SecretAliases  []string  `json:"secret_aliases"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxReads       int       `json:"max_reads"`
	RemainingReads int       `json:"remaining_reads"`
	OverrideEnv    bool      `json:"override_env"`
}

type ItemDescribeResponsePayload struct {
	Item itemmetadata.Metadata `json:"item"`
}

type CommandStartedPayload struct {
	ChildPID int `json:"child_pid"`
}

type CommandCompletedPayload struct {
	ExitCode int    `json:"exit_code"`
	Signal   string `json:"signal,omitempty"`
}

type StatusPayload struct {
	PID int `json:"pid"`
}

type HelperHelloPayload struct {
	Protocol   int    `json:"protocol"`
	AppVersion string `json:"app_version"`
	BuildID    string `json:"build_id,omitempty"`
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	TeamID     string `json:"team_id,omitempty"`
	BundleID   string `json:"bundle_id,omitempty"`
}

type OnePasswordStatusPayload struct {
	Account string `json:"account"`
}

func NewEnvelope(messageType MessageType, correlation Correlation, payload any) (Envelope, error) {
	raw, err := marshalPayload(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Version:   ProtocolVersion,
		Type:      messageType,
		RequestID: correlation.RequestID,
		Nonce:     correlation.Nonce,
		Payload:   raw,
	}, nil
}

func DecodePayload[T any](env Envelope) (T, error) {
	var out T
	if len(env.Payload) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(env.Payload, &out); err != nil {
		return out, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	return out, nil
}

func DecodeRequiredPayload[T any](env Envelope) (T, error) {
	var out T
	payload := bytes.TrimSpace(env.Payload)
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		return out, fmt.Errorf("%w: %s missing payload", ErrMalformedEnvelope, env.Type)
	}
	return DecodePayload[T](env)
}

func ValidateEnvelope(env Envelope) error {
	if env.Version != ProtocolVersion {
		return fmt.Errorf("%w: %d", ErrProtocolVersion, env.Version)
	}
	if env.Type == "" {
		return fmt.Errorf("%w: missing type", ErrMalformedEnvelope)
	}
	return nil
}

func ReadEnvelopeFrame(reader *bufio.Reader, maxBytes int64) (Envelope, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxProtocolFrameBytes
	}

	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			if int64(len(line))+int64(len(chunk)) > maxBytes {
				return Envelope{}, fmt.Errorf("%w: max %d bytes", ErrProtocolFrameSize, maxBytes)
			}
			line = append(line, chunk...)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Envelope{}, io.EOF
		}
		if errors.Is(err, io.EOF) {
			return Envelope{}, fmt.Errorf("%w: unterminated JSON frame", ErrMalformedEnvelope)
		}
		return Envelope{}, err
	}

	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Envelope{}, fmt.Errorf("%w: empty frame", ErrMalformedEnvelope)
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	return env, nil
}

func marshalPayload(payload any) (json.RawMessage, error) {
	if payload == nil {
		return nil, nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}
	return raw, nil
}
