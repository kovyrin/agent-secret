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
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type PeerValidator interface {
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
	broker        *Broker
	approvals     ApprovalEndpoint
	validator     PeerValidator
	execValidator ExecPeerValidator
	maxFrameBytes int64
	readTimeout   time.Duration
	stopOnce      sync.Once
	stop          chan struct{}
}

type ServerOptions struct {
	Broker        *Broker
	Approvals     ApprovalEndpoint
	Validator     PeerValidator
	ExecValidator ExecPeerValidator
	MaxFrameBytes int64
	ReadTimeout   time.Duration
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
		maxFrameBytes = DefaultMaxProtocolFrameBytes
	}
	readTimeout := opts.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultProtocolReadTimeout
	}
	return &Server{
		broker:        opts.Broker,
		approvals:     opts.Approvals,
		validator:     validator,
		execValidator: execValidator,
		maxFrameBytes: maxFrameBytes,
		readTimeout:   readTimeout,
		stop:          make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	listener, err := ListenUnix(path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	//nolint:gosec // G703: path is the socket just created by ListenUnix after private-directory validation.
	defer func() { _ = os.Remove(path) }()
	return s.Serve(ctx, listener)
}

func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	errs := make(chan error, 1)
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
				errs <- err
				return <-errs
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
		_ = writeError(conn, "", "", "peer_rejected", err)
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
			if errors.Is(err, ErrProtocolFrameSize) {
				_ = writeErrorEncoder(encoder, "", "", "frame_too_large", err)
			} else if errors.Is(err, ErrMalformedEnvelope) {
				_ = writeErrorEncoder(encoder, "", "", "bad_envelope", err)
			}
			return
		}
		if err := validateEnvelope(env); err != nil {
			_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_envelope", err)
			continue
		}

		nextReadTimeout = s.readTimeout
		if commandStarted {
			nextReadTimeout = 0
		}

		switch env.Type {
		case TypeDaemonStatus:
			_ = writeOK(encoder, env.RequestID, env.Nonce, StatusPayload{PID: os.Getpid()})
		case TypeDaemonStop:
			peer, err := s.peerInfo(conn)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "peer_rejected", err)
				continue
			}
			if err := s.execValidator.ValidateExecPeer(peer); err != nil {
				s.broker.recordDaemonStopAttempt(ctx, daemonStopAuditEvent(peer, err))
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
				continue
			}
			_ = writeOK(encoder, env.RequestID, env.Nonce, StatusPayload{PID: os.Getpid()})
			s.stopWithAudit(ctx, daemonStopAuditEvent(peer, nil))
			return
		case TypeApprovalPending:
			if s.approvals == nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "approval_unavailable", ErrApprovalUnavailable)
				continue
			}
			peer, err := s.peerInfo(conn)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "peer_rejected", err)
				continue
			}
			payload, err := s.approvals.FetchPending(ctx, peer)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
				continue
			}
			if err := writeOK(encoder, payload.RequestID, payload.Nonce, payload); err == nil {
				nextReadTimeout = s.approvalDecisionReadTimeout(payload.ExpiresAt)
			}
		case TypeApprovalDecision:
			if s.approvals == nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "approval_unavailable", ErrApprovalUnavailable)
				continue
			}
			payload, err := DecodePayload[ApprovalDecisionPayload](env)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_approval_decision", err)
				continue
			}
			peer, err := s.peerInfo(conn)
			if err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "peer_rejected", err)
				continue
			}
			if err := s.approvals.SubmitDecision(ctx, peer, payload); err != nil {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
				continue
			}
			_ = writeOK(encoder, env.RequestID, env.Nonce, nil)
		case TypeRequestExec:
			if activeRequestID != "" {
				_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(ErrRequestAlreadyActive), ErrRequestAlreadyActive)
				continue
			}
			if requestID := s.handleRequestExec(ctx, conn, encoder, env); requestID != "" {
				activeRequestID = requestID
				commandStarted = false
				nextReadTimeout = s.readTimeout
			}
		case TypeCommandStarted:
			if s.handleCommandStarted(ctx, conn, encoder, env) {
				commandStarted = true
				nextReadTimeout = 0
			}
		case TypeCommandCompleted:
			if s.handleCommandCompleted(ctx, conn, encoder, env) {
				activeRequestID = ""
				commandStarted = false
				nextReadTimeout = s.readTimeout
			}
		default:
			_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_type", fmt.Errorf("%w: %s", ErrProtocolType, env.Type))
		}
	}
}

func (s *Server) handleRequestExec(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env Envelope,
) string {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return ""
	}
	req, err := DecodePayload[request.ExecRequest](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_request", err)
		return ""
	}
	if err := req.ValidateForDaemon(); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_request", err)
		return ""
	}
	grant, err := s.broker.HandleExec(ctx, env.RequestID, env.Nonce, req)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return ""
	}
	if err := s.broker.MarkPayloadDelivered(env.RequestID); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return ""
	}
	_ = writeOK(encoder, env.RequestID, env.Nonce, ExecResponsePayload{
		Env:           grant.Env,
		SecretAliases: grant.SecretAliases,
	})
	return env.RequestID
}

func (s *Server) handleCommandStarted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env Envelope,
) bool {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return false
	}
	payload, err := DecodePayload[CommandStartedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_command_started", err)
		return false
	}
	if err := s.broker.ReportStarted(ctx, env.RequestID, env.Nonce, payload.ChildPID); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return false
	}
	_ = writeOK(encoder, env.RequestID, env.Nonce, nil)
	return true
}

func (s *Server) handleCommandCompleted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env Envelope,
) bool {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return false
	}
	payload, err := DecodePayload[CommandCompletedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_command_completed", err)
		return false
	}
	if err := s.broker.ReportCompleted(ctx, env.RequestID, env.Nonce, payload.ExitCode, payload.Signal); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return false
	}
	_ = writeOK(encoder, env.RequestID, env.Nonce, nil)
	return true
}

func (s *Server) peerInfo(conn *net.UnixConn) (peercred.Info, error) {
	provider, ok := s.validator.(interface {
		Info(conn *net.UnixConn) (peercred.Info, error)
	})
	if ok {
		return provider.Info(conn)
	}
	return peercred.Inspect(conn)
}

func (s *Server) readEnvelope(conn *net.UnixConn, reader *bufio.Reader, timeout time.Duration) (Envelope, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return Envelope{}, fmt.Errorf("set daemon read deadline: %w", err)
		}
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	return readEnvelopeFrame(reader, s.maxFrameBytes)
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
		event.ErrorCode = codeForError(err)
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

func writeOK(encoder *json.Encoder, requestID string, nonce string, payload any) error {
	env, err := NewEnvelope(TypeOK, requestID, nonce, payload)
	if err != nil {
		return err
	}
	return encoder.Encode(env)
}

func writeError(conn *net.UnixConn, requestID string, nonce string, code string, err error) error {
	return writeErrorEncoder(json.NewEncoder(conn), requestID, nonce, code, err)
}

func writeErrorEncoder(encoder *json.Encoder, requestID string, nonce string, code string, err error) error {
	payload := ErrorPayload{Code: code, Message: err.Error()}
	env, marshalErr := NewEnvelope(TypeError, requestID, nonce, payload)
	if marshalErr != nil {
		return marshalErr
	}
	return encoder.Encode(env)
}

func codeForError(err error) string {
	switch {
	case errors.Is(err, ErrApprovalDenied):
		return "approval_denied"
	case errors.Is(err, ErrAuditRequired):
		return "audit_failed"
	case errors.Is(err, ErrInvalidNonce):
		return "invalid_nonce"
	case errors.Is(err, ErrApproverPeerMismatch):
		return "approver_peer_mismatch"
	case errors.Is(err, ErrApproverIdentity):
		return "approver_identity_mismatch"
	case errors.Is(err, ErrNoPendingApproval):
		return "no_pending_approval"
	case errors.Is(err, ErrRequestAlreadyActive):
		return "request_active"
	case errors.Is(err, ErrRequestExpired):
		return "request_expired"
	case errors.Is(err, ErrStaleApproval):
		return "stale_approval"
	case errors.Is(err, ErrUntrustedClient):
		return "untrusted_client"
	default:
		return "request_failed"
	}
}
