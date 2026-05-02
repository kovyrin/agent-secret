package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const ProtocolVersion = 1
const DefaultMaxProtocolFrameBytes int64 = 1 << 20

const (
	TypeDaemonStatus     = "daemon.status"
	TypeDaemonStop       = "daemon.stop"
	TypeApprovalPending  = "approval.pending"
	TypeApprovalDecision = "approval.decision"
	TypeRequestExec      = "request.exec"
	TypeCommandStarted   = "command.started"
	TypeCommandCompleted = "command.completed"
	TypeOK               = "ok"
	TypeError            = "error"
)

var (
	ErrMalformedEnvelope = errors.New("malformed protocol envelope")
	ErrProtocolFrameSize = errors.New("protocol frame exceeds maximum size")
	ErrProtocolVersion   = errors.New("unsupported protocol version")
	ErrProtocolType      = errors.New("unsupported protocol message type")
)

type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	Nonce     string          `json:"nonce,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ExecResponsePayload struct {
	Env           map[string]string `json:"env"`
	SecretAliases []string          `json:"secret_aliases"`
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

func NewEnvelope(messageType string, requestID string, nonce string, payload any) (Envelope, error) {
	raw, err := marshalPayload(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Version:   ProtocolVersion,
		Type:      messageType,
		RequestID: requestID,
		Nonce:     nonce,
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

func validateEnvelope(env Envelope) error {
	if env.Version != ProtocolVersion {
		return fmt.Errorf("%w: %d", ErrProtocolVersion, env.Version)
	}
	if env.Type == "" {
		return fmt.Errorf("%w: missing type", ErrMalformedEnvelope)
	}
	return nil
}

func readEnvelopeFrame(reader *bufio.Reader, maxBytes int64) (Envelope, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxProtocolFrameBytes
	}
	var frame []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if int64(len(frame)+len(chunk)) > maxBytes {
			return Envelope{}, fmt.Errorf("%w: max %d bytes", ErrProtocolFrameSize, maxBytes)
		}
		frame = append(frame, chunk...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(frame) == 0 {
			return Envelope{}, io.EOF
		}
		if errors.Is(err, io.EOF) {
			return Envelope{}, fmt.Errorf("%w: unterminated JSON frame", ErrMalformedEnvelope)
		}
		return Envelope{}, err
	}

	frame = bytes.TrimSpace(frame)
	if len(frame) == 0 {
		return Envelope{}, fmt.Errorf("%w: empty frame", ErrMalformedEnvelope)
	}
	var env Envelope
	if err := json.Unmarshal(frame, &env); err != nil {
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
		return nil, fmt.Errorf("marshal protocol payload: %w", err)
	}
	return raw, nil
}
