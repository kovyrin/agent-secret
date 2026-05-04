package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type PeerValidator interface {
	Info(conn *net.UnixConn) (peercred.Info, error)
	Validate(conn *net.UnixConn) error
}

type SameUIDValidator struct{}

func (SameUIDValidator) Info(conn *net.UnixConn) (peercred.Info, error) {
	return peercred.Inspect(conn)
}

func (SameUIDValidator) Validate(conn *net.UnixConn) error {
	info, err := SameUIDValidator{}.Info(conn)
	if err != nil {
		return err
	}
	if info.UID != os.Getuid() {
		return fmt.Errorf("%w: uid %d != %d", peercred.ErrPolicyMismatch, info.UID, os.Getuid())
	}
	return nil
}

type Server struct {
	broker                  *Broker
	approvals               approval.ApprovalEndpoint
	validator               PeerValidator
	execValidator           ExecPeerValidator
	maxFrameBytes           int64
	readTimeout             time.Duration
	beforeExecResponseWrite func()
	stopOnce                sync.Once
	stop                    chan struct{}
}

type ServerOptions struct {
	Broker                  *Broker
	Approvals               approval.ApprovalEndpoint
	Validator               PeerValidator
	ExecValidator           ExecPeerValidator
	MaxFrameBytes           int64
	ReadTimeout             time.Duration
	beforeExecResponseWrite func()
}

const DefaultProtocolReadTimeout = 30 * time.Second

func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Broker == nil {
		return nil, errors.New("broker is required")
	}
	validator := opts.Validator
	if validator == nil {
		validator = SameUIDValidator{}
	}
	execValidator := opts.ExecValidator
	if execValidator == nil {
		execValidator = NewTrustedExecutableValidator(DefaultTrustedClientPaths())
	}
	maxFrameBytes := opts.MaxFrameBytes
	if maxFrameBytes <= 0 {
		maxFrameBytes = protocol.DefaultMaxProtocolFrameBytes
	}
	readTimeout := opts.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultProtocolReadTimeout
	}
	return &Server{
		broker:                  opts.Broker,
		approvals:               opts.Approvals,
		validator:               validator,
		execValidator:           execValidator,
		maxFrameBytes:           maxFrameBytes,
		readTimeout:             readTimeout,
		beforeExecResponseWrite: opts.beforeExecResponseWrite,
		stop:                    make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	listener, err := socket.ListenUnix(path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	//nolint:gosec // G703: path is the socket just created by ListenUnix after private-directory validation.
	defer func() { _ = os.Remove(path) }()
	return s.Serve(ctx, listener)
}

func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		<-s.stop
		_ = listener.Close()
	}()

	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.stop:
				return nil
			default:
				return err
			}
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) Stop(ctx context.Context) {
	s.stopWithAudit(ctx, audit.Event{Type: audit.EventDaemonStop})
}

func (s *Server) stopWithAudit(ctx context.Context, event audit.Event) {
	s.broker.stopWithAudit(ctx, event)
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	if err := s.validator.Validate(conn); err != nil {
		_ = writeError(conn, protocol.Correlation{}, protocol.ErrorCodePeerRejected, err)
		return
	}

	reader := bufio.NewReader(conn)
	encoder := json.NewEncoder(conn)
	activeRequestID := ""
	commandStarted := false
	nextReadTimeout := s.readTimeout
	for {
		env, err := s.readEnvelope(conn, reader, nextReadTimeout)
		if err != nil {
			if activeRequestID != "" {
				s.broker.ClientDisconnected(ctx, activeRequestID)
			}
			if errors.Is(err, protocol.ErrProtocolFrameSize) {
				_ = writeErrorEncoder(encoder, protocol.Correlation{}, protocol.ErrorCodeFrameTooLarge, err)
			} else if errors.Is(err, protocol.ErrMalformedEnvelope) {
				_ = writeErrorEncoder(encoder, protocol.Correlation{}, protocol.ErrorCodeBadEnvelope, err)
			}
			return
		}
		if err := protocol.ValidateEnvelope(env); err != nil {
			_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadEnvelope, err)
			continue
		}
		if s.stopped() && env.Type != protocol.TypeDaemonStatus {
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrDaemonStopped), ErrDaemonStopped)
			return
		}

		nextReadTimeout = s.readTimeout
		if commandStarted {
			nextReadTimeout = 0
		}

		//nolint:exhaustive // Response envelopes are invalid client requests; default rejects them with unknown request types.
		switch env.Type {
		case protocol.TypeDaemonStatus:
			_ = writeOK(encoder, env.Correlation(), protocol.StatusPayload{PID: os.Getpid()})
		case protocol.TypeDaemonStop:
			if s.handleDaemonStop(ctx, conn, encoder, env) {
				return
			}
		case protocol.TypeApprovalPending:
			if payload, ok := s.handleApprovalPending(ctx, conn, encoder, env); ok {
				nextReadTimeout = s.approvalDecisionReadTimeout(payload.ExpiresAt)
			}
		case protocol.TypeApprovalDecision:
			if s.approvals == nil {
				_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeApprovalUnavailable, ErrApprovalUnavailable)
				continue
			}
			payload, err := protocol.DecodePayload[approval.ApprovalDecisionPayload](env)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadApprovalDecision, err)
				continue
			}
			peer, err := s.peerInfo(conn)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodePeerRejected, err)
				continue
			}
			if err := s.approvals.SubmitDecision(ctx, peer, payload); err != nil {
				_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
				continue
			}
			_ = writeOK(encoder, env.Correlation(), nil)
		case protocol.TypeRequestExec:
			if activeRequestID != "" {
				_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrRequestAlreadyActive), ErrRequestAlreadyActive)
				continue
			}
			if requestID := s.handleRequestExec(ctx, conn, encoder, env); requestID != "" {
				activeRequestID = requestID
				commandStarted = false
				nextReadTimeout = s.readTimeout
			}
		case protocol.TypeCommandStarted:
			if !s.lifecycleRequestMatchesConnection(encoder, env, activeRequestID) {
				continue
			}
			if s.handleCommandStarted(ctx, conn, encoder, env) {
				commandStarted = true
				nextReadTimeout = 0
			}
		case protocol.TypeCommandCompleted:
			if !s.lifecycleRequestMatchesConnection(encoder, env, activeRequestID) {
				continue
			}
			if s.handleCommandCompleted(ctx, conn, encoder, env) {
				activeRequestID = ""
				commandStarted = false
				nextReadTimeout = s.readTimeout
			}
		default:
			_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadType, fmt.Errorf("%w: %s", protocol.ErrProtocolType, env.Type))
		}
	}
}

func (s *Server) lifecycleRequestMatchesConnection(
	encoder *json.Encoder,
	env protocol.Envelope,
	activeRequestID string,
) bool {
	if activeRequestID != "" && env.RequestID == activeRequestID {
		return true
	}
	_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrInvalidNonce), ErrInvalidNonce)
	return false
}

func (s *Server) handleApprovalPending(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) (approval.ApprovalRequestPayload, bool) {
	if s.approvals == nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeApprovalUnavailable, ErrApprovalUnavailable)
		return approval.ApprovalRequestPayload{}, false
	}
	peer, err := s.peerInfo(conn)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodePeerRejected, err)
		return approval.ApprovalRequestPayload{}, false
	}
	payload, err := s.approvals.FetchPending(ctx, peer)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return approval.ApprovalRequestPayload{}, false
	}
	correlation := protocol.Correlation{RequestID: payload.RequestID, Nonce: payload.Nonce}
	if err := writeOK(encoder, correlation, payload); err != nil {
		return approval.ApprovalRequestPayload{}, false
	}
	return payload, true
}

func (s *Server) handleDaemonStop(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) bool {
	peer, err := s.peerInfo(conn)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodePeerRejected, err)
		return false
	}
	if err := s.execValidator.ValidateExecPeer(peer); err != nil {
		s.broker.recordDaemonStopAttempt(ctx, daemonStopAuditEvent(peer, err))
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return false
	}
	s.stopWithAudit(ctx, daemonStopAuditEvent(peer, nil))
	_ = writeOK(encoder, env.Correlation(), protocol.StatusPayload{PID: os.Getpid()})
	return true
}

func (s *Server) handleRequestExec(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) string {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	req, err := protocol.DecodePayload[request.ExecRequest](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return ""
	}
	req = req.WithReceiptTime(s.broker.now())
	if err := req.ValidateForDaemon(); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return ""
	}
	delivery, err := s.broker.handleExecDelivery(ctx, env.Correlation(), req)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	if err := delivery.deliver(func(payload protocol.ExecResponsePayload, expiresAt time.Time) error {
		if s.stopped() {
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrDaemonStopped), ErrDaemonStopped)
			return ErrDaemonStopped
		}
		if s.beforeExecResponseWrite != nil {
			s.beforeExecResponseWrite()
		}
		clearWriteDeadline, err := s.setExecResponseWriteDeadline(conn, expiresAt)
		if err != nil {
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
			return err
		}
		defer clearWriteDeadline()
		return writeOK(encoder, env.Correlation(), payload)
	}); err != nil {
		return ""
	}
	return env.RequestID
}

func (s *Server) setExecResponseWriteDeadline(conn *net.UnixConn, expiresAt time.Time) (func(), error) {
	if expiresAt.IsZero() {
		return func() {}, nil
	}
	remaining := expiresAt.Sub(s.broker.now())
	if remaining <= 0 {
		return func() {}, ErrRequestExpired
	}
	if err := conn.SetWriteDeadline(time.Now().Add(remaining)); err != nil {
		return func() {}, fmt.Errorf("set exec response write deadline: %w", err)
	}
	return func() { _ = conn.SetWriteDeadline(time.Time{}) }, nil
}

func (s *Server) handleCommandStarted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) bool {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return false
	}
	payload, err := protocol.DecodePayload[protocol.CommandStartedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadCommandStarted, err)
		return false
	}
	if err := s.broker.ReportStarted(ctx, env.Correlation(), payload.ChildPID); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return false
	}
	_ = writeOK(encoder, env.Correlation(), nil)
	return true
}

func (s *Server) handleCommandCompleted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) bool {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return false
	}
	payload, err := protocol.DecodePayload[protocol.CommandCompletedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadCommandCompleted, err)
		return false
	}
	if err := s.broker.ReportCompleted(ctx, env.Correlation(), payload.ExitCode, payload.Signal); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return false
	}
	_ = writeOK(encoder, env.Correlation(), nil)
	return true
}

func (s *Server) peerInfo(conn *net.UnixConn) (peercred.Info, error) {
	return s.validator.Info(conn)
}

func (s *Server) readEnvelope(conn *net.UnixConn, reader *bufio.Reader, timeout time.Duration) (protocol.Envelope, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return protocol.Envelope{}, fmt.Errorf("set daemon read deadline: %w", err)
		}
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	return protocol.ReadEnvelopeFrame(reader, s.maxFrameBytes)
}

func (s *Server) approvalDecisionReadTimeout(expiresAt time.Time) time.Duration {
	if s.readTimeout <= 0 {
		return 0
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return s.readTimeout
	}
	return remaining + s.readTimeout
}

func daemonStopAuditEvent(peer peercred.Info, err error) audit.Event {
	pid := peer.PID
	uid := peer.UID
	event := audit.Event{
		Type:          audit.EventDaemonStop,
		RequesterPID:  &pid,
		RequesterUID:  &uid,
		RequesterPath: peer.ExecutablePath,
	}
	if err != nil {
		event.ErrorCode = auditErrorCode(codeForError(err))
	}
	return event
}

func (s *Server) validateTrustedClientPeer(conn *net.UnixConn) error {
	peer, err := s.peerInfo(conn)
	if err != nil {
		return err
	}
	return s.execValidator.ValidateExecPeer(peer)
}

func writeOK(encoder *json.Encoder, correlation protocol.Correlation, payload any) error {
	env, err := protocol.NewEnvelope(protocol.TypeOK, correlation, payload)
	if err != nil {
		return err
	}
	return encoder.Encode(env)
}

func writeError(conn *net.UnixConn, correlation protocol.Correlation, code protocol.ErrorCode, err error) error {
	return writeErrorEncoder(json.NewEncoder(conn), correlation, code, err)
}

func writeErrorEncoder(encoder *json.Encoder, correlation protocol.Correlation, code protocol.ErrorCode, err error) error {
	payload := protocol.ErrorPayload{Code: code, Message: err.Error()}
	env, marshalErr := protocol.NewEnvelope(protocol.TypeError, correlation, payload)
	if marshalErr != nil {
		return marshalErr
	}
	return encoder.Encode(env)
}

func codeForError(err error) protocol.ErrorCode {
	switch {
	case errors.Is(err, ErrApprovalDenied):
		return protocol.ErrorCodeApprovalDenied
	case errors.Is(err, ErrAuditRequired):
		return protocol.ErrorCodeAuditFailed
	case errors.Is(err, ErrInvalidNonce):
		return protocol.ErrorCodeInvalidNonce
	case errors.Is(err, approval.ErrApproverPeerMismatch):
		return protocol.ErrorCodeApproverPeerMismatch
	case errors.Is(err, approval.ErrApproverIdentity):
		return protocol.ErrorCodeApproverIdentityMismatch
	case errors.Is(err, approval.ErrNoPendingApproval):
		return protocol.ErrorCodeNoPendingApproval
	case errors.Is(err, ErrRequestAlreadyActive):
		return protocol.ErrorCodeRequestActive
	case errors.Is(err, ErrDaemonStopped):
		return protocol.ErrorCodeDaemonStopped
	case errors.Is(err, ErrRequestExpired):
		return protocol.ErrorCodeRequestExpired
	case errors.Is(err, approval.ErrStaleApproval):
		return protocol.ErrorCodeStaleApproval
	case errors.Is(err, ErrUntrustedClient):
		return protocol.ErrorCodeUntrustedClient
	case errors.Is(err, context.Canceled):
		return protocol.ErrorCodeContextCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.ErrorCodeContextDeadlineExceeded
	case errors.Is(err, ErrSecretResolveFailed):
		return protocol.ErrorCodeResolveFailed
	default:
		return protocol.ErrorCodeRequestFailed
	}
}

func (s *Server) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}
