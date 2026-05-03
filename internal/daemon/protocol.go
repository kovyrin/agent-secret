package daemon

import (
	"bufio"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
)

const ProtocolVersion = protocol.ProtocolVersion
const DefaultMaxProtocolFrameBytes = protocol.DefaultMaxProtocolFrameBytes

type MessageType = protocol.MessageType

const (
	TypeDaemonStatus     = protocol.TypeDaemonStatus
	TypeDaemonStop       = protocol.TypeDaemonStop
	TypeApprovalPending  = protocol.TypeApprovalPending
	TypeApprovalDecision = protocol.TypeApprovalDecision
	TypeRequestExec      = protocol.TypeRequestExec
	TypeCommandStarted   = protocol.TypeCommandStarted
	TypeCommandCompleted = protocol.TypeCommandCompleted
	TypeOK               = protocol.TypeOK
	TypeError            = protocol.TypeError
)

type ErrorCode = protocol.ErrorCode

const (
	ErrorCodeApprovalDenied           = protocol.ErrorCodeApprovalDenied
	ErrorCodeApprovalUnavailable      = protocol.ErrorCodeApprovalUnavailable
	ErrorCodeApproverIdentityMismatch = protocol.ErrorCodeApproverIdentityMismatch
	ErrorCodeApproverPeerMismatch     = protocol.ErrorCodeApproverPeerMismatch
	ErrorCodeAuditFailed              = protocol.ErrorCodeAuditFailed
	ErrorCodeBadApprovalDecision      = protocol.ErrorCodeBadApprovalDecision
	ErrorCodeBadCommandCompleted      = protocol.ErrorCodeBadCommandCompleted
	ErrorCodeBadCommandStarted        = protocol.ErrorCodeBadCommandStarted
	ErrorCodeBadEnvelope              = protocol.ErrorCodeBadEnvelope
	ErrorCodeBadRequest               = protocol.ErrorCodeBadRequest
	ErrorCodeBadType                  = protocol.ErrorCodeBadType
	ErrorCodeContextCanceled          = protocol.ErrorCodeContextCanceled
	ErrorCodeContextDeadlineExceeded  = protocol.ErrorCodeContextDeadlineExceeded
	ErrorCodeDaemonStopped            = protocol.ErrorCodeDaemonStopped
	ErrorCodeFrameTooLarge            = protocol.ErrorCodeFrameTooLarge
	ErrorCodeInvalidNonce             = protocol.ErrorCodeInvalidNonce
	ErrorCodeNoPendingApproval        = protocol.ErrorCodeNoPendingApproval
	ErrorCodePeerRejected             = protocol.ErrorCodePeerRejected
	ErrorCodeRequestActive            = protocol.ErrorCodeRequestActive
	ErrorCodeRequestExpired           = protocol.ErrorCodeRequestExpired
	ErrorCodeRequestFailed            = protocol.ErrorCodeRequestFailed
	ErrorCodeResolveFailed            = protocol.ErrorCodeResolveFailed
	ErrorCodeStaleApproval            = protocol.ErrorCodeStaleApproval
	ErrorCodeUntrustedClient          = protocol.ErrorCodeUntrustedClient
)

var (
	ErrMalformedEnvelope = protocol.ErrMalformedEnvelope
	ErrProtocolFrameSize = protocol.ErrProtocolFrameSize
	ErrProtocolVersion   = protocol.ErrProtocolVersion
	ErrProtocolType      = protocol.ErrProtocolType
)

type Envelope = protocol.Envelope
type ErrorPayload = protocol.ErrorPayload
type ExecResponsePayload = protocol.ExecResponsePayload
type CommandStartedPayload = protocol.CommandStartedPayload
type CommandCompletedPayload = protocol.CommandCompletedPayload
type StatusPayload = protocol.StatusPayload

func NewEnvelope(messageType MessageType, requestID string, nonce string, payload any) (Envelope, error) {
	return protocol.NewEnvelope(messageType, requestID, nonce, payload)
}

func DecodePayload[T any](env Envelope) (T, error) {
	return protocol.DecodePayload[T](env)
}

func validateEnvelope(env Envelope) error {
	return protocol.ValidateEnvelope(env)
}

func readEnvelopeFrame(reader *bufio.Reader, maxBytes int64) (Envelope, error) {
	return protocol.ReadEnvelopeFrame(reader, maxBytes)
}
