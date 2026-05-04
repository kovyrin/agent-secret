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
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
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
	broker                  *daemonbroker.Broker
	approvals               approval.ApprovalEndpoint
	validator               PeerValidator
	execValidator           peertrust.ExecValidator
	onePasswordCheck        func(context.Context) error
	maxFrameBytes           int64
	readTimeout             time.Duration
	beforeRead              func(time.Duration)
	beforeExecResponseWrite func()
	stopOnce                sync.Once
	stop                    chan struct{}
}

type ServerOptions struct {
	Broker                  *daemonbroker.Broker
	Approvals               approval.ApprovalEndpoint
	Validator               PeerValidator
	ExecValidator           peertrust.ExecValidator
	OnePasswordCheck        func(context.Context) error
	MaxFrameBytes           int64
	ReadTimeout             time.Duration
	beforeRead              func(time.Duration)
	beforeExecResponseWrite func()
}

const DefaultProtocolReadTimeout = 30 * time.Second

var (
	ErrRequestAlreadyActive        = errors.New("connection already has an active exec request")
	ErrOnePasswordCheckUnavailable = errors.New("1Password desktop integration check unavailable")
)

type connectionState struct {
	defaultReadTimeout time.Duration
	nextReadTimeout    time.Duration
	activeRequestID    string
	commandStarted     bool
}

func newConnectionState(readTimeout time.Duration) connectionState {
	return connectionState{defaultReadTimeout: readTimeout, nextReadTimeout: readTimeout}
}

func (s *connectionState) readTimeout() time.Duration {
	return s.nextReadTimeout
}

func (s *connectionState) resetReadTimeout() {
	if s.commandStarted {
		s.nextReadTimeout = 0
		return
	}
	s.nextReadTimeout = s.defaultReadTimeout
}

func (s *connectionState) waitForApprovalDecision(timeout time.Duration) {
	s.nextReadTimeout = timeout
}

func (s *connectionState) beginExec(requestID string) {
	s.activeRequestID = requestID
	s.commandStarted = false
	s.nextReadTimeout = s.defaultReadTimeout
}

func (s *connectionState) markStarted() {
	s.commandStarted = true
	s.nextReadTimeout = 0
}

func (s *connectionState) markCompleted() {
	s.activeRequestID = ""
	s.commandStarted = false
	s.nextReadTimeout = s.defaultReadTimeout
}

func (s *connectionState) hasActiveRequest() bool {
	return s.activeRequestID != ""
}

func (s *connectionState) matchesRequest(requestID string) bool {
	return s.activeRequestID != "" && requestID == s.activeRequestID
}

func (s *connectionState) disconnectRequestID() string {
	return s.activeRequestID
}

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
		defaultClientPaths, err := peertrust.DefaultClientPaths()
		if err != nil {
			return nil, fmt.Errorf("default exec validator trusted clients: %w", err)
		}
		execValidator = peertrust.NewExecutableValidator(defaultClientPaths)
	}
	onePasswordCheck := opts.OnePasswordCheck
	if onePasswordCheck == nil {
		onePasswordCheck = func(context.Context) error { return ErrOnePasswordCheckUnavailable }
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
		onePasswordCheck:        onePasswordCheck,
		maxFrameBytes:           maxFrameBytes,
		readTimeout:             readTimeout,
		beforeRead:              opts.beforeRead,
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
	s.broker.StopWithAuditEvent(ctx, event)
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
	state := newConnectionState(s.readTimeout)
	for {
		env, err := s.readEnvelope(conn, reader, state.readTimeout())
		if err != nil {
			if requestID := state.disconnectRequestID(); requestID != "" {
				s.broker.ClientDisconnected(ctx, requestID)
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
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(daemonbroker.ErrDaemonStopped), daemonbroker.ErrDaemonStopped)
			return
		}

		state.resetReadTimeout()

		//nolint:exhaustive // Response envelopes are invalid client requests; default rejects them with unknown request types.
		switch env.Type {
		case protocol.TypeDaemonStatus, protocol.TypeOnePasswordStatus:
			s.handleStatusRequest(ctx, encoder, env)
		case protocol.TypeDaemonStop:
			if s.handleDaemonStop(ctx, conn, encoder, env) {
				return
			}
		case protocol.TypeApprovalPending:
			if payload, ok := s.handleApprovalPending(ctx, conn, encoder, env); ok {
				state.waitForApprovalDecision(s.approvalDecisionReadTimeout(payload.ExpiresAt))
			}
		case protocol.TypeApprovalDecision:
			if s.approvals == nil {
				_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeApprovalUnavailable, approval.ErrUnavailable)
				continue
			}
			payload, err := protocol.DecodeRequiredPayload[approval.ApprovalDecisionPayload](env)
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
			if state.hasActiveRequest() {
				_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrRequestAlreadyActive), ErrRequestAlreadyActive)
				continue
			}
			if requestID := s.handleRequestExec(ctx, conn, encoder, env); requestID != "" {
				state.beginExec(requestID)
			}
		case protocol.TypeCommandStarted:
			if !s.lifecycleRequestMatchesConnection(encoder, env, &state) {
				continue
			}
			if s.handleCommandStarted(ctx, conn, encoder, env) {
				state.markStarted()
			}
		case protocol.TypeCommandCompleted:
			if !s.lifecycleRequestMatchesConnection(encoder, env, &state) {
				continue
			}
			if s.handleCommandCompleted(ctx, conn, encoder, env) {
				state.markCompleted()
			}
		default:
			_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadType, fmt.Errorf("%w: %s", protocol.ErrProtocolType, env.Type))
		}
	}
}

func (s *Server) handleStatusRequest(ctx context.Context, encoder *json.Encoder, env protocol.Envelope) {
	if env.Type == protocol.TypeDaemonStatus {
		_ = writeOK(encoder, env.Correlation(), protocol.StatusPayload{PID: os.Getpid()})
		return
	}
	if err := s.onePasswordCheck(ctx); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeResolveFailed, err)
		return
	}
	_ = writeOK(encoder, env.Correlation(), nil)
}

func (s *Server) lifecycleRequestMatchesConnection(
	encoder *json.Encoder,
	env protocol.Envelope,
	state *connectionState,
) bool {
	if state.matchesRequest(env.RequestID) {
		return true
	}
	_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(protocol.ErrInvalidNonce), protocol.ErrInvalidNonce)
	return false
}

func (s *Server) handleApprovalPending(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) (approval.ApprovalRequestPayload, bool) {
	if s.approvals == nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeApprovalUnavailable, approval.ErrUnavailable)
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
		s.broker.RecordStopAttempt(ctx, daemonStopAuditEvent(peer, err))
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
	req, err := protocol.DecodeRequiredPayload[request.ExecRequest](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return ""
	}
	req = req.WithReceiptTime(s.broker.Now())
	if err := req.ValidateForDaemon(); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return ""
	}
	_, err = s.broker.HandleExecDelivery(ctx, env.Correlation(), req, func(
		payload protocol.ExecResponsePayload,
		expiresAt time.Time,
		beforeWrite func() error,
	) error {
		if s.beforeExecResponseWrite != nil {
			s.beforeExecResponseWrite()
		}
		clearWriteDeadline, err := s.setExecResponseWriteDeadline(conn, expiresAt)
		if err != nil {
			return err
		}
		defer clearWriteDeadline()
		if err := beforeWrite(); err != nil {
			return err
		}
		if err := writeOK(encoder, env.Correlation(), payload); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	return env.RequestID
}

func (s *Server) setExecResponseWriteDeadline(conn *net.UnixConn, expiresAt time.Time) (func(), error) {
	if expiresAt.IsZero() {
		return func() {}, nil
	}
	remaining := expiresAt.Sub(s.broker.Now())
	if remaining <= 0 {
		return func() {}, approval.ErrRequestExpired
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
	payload, err := protocol.DecodeRequiredPayload[protocol.CommandStartedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadCommandStarted, err)
		return false
	}
	if payload.ChildPID <= 0 {
		err := fmt.Errorf("%w: command.started missing child pid", protocol.ErrMalformedEnvelope)
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
	payload, err := protocol.DecodeRequiredPayload[protocol.CommandCompletedPayload](env)
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
	if s.beforeRead != nil {
		s.beforeRead(timeout)
	}
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
		event.ErrorCode = audit.ErrorCode(codeForError(err))
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
	case errors.Is(err, approval.ErrApprovalDenied):
		return protocol.ErrorCodeApprovalDenied
	case errors.Is(err, daemonbroker.ErrAuditRequired):
		return protocol.ErrorCodeAuditFailed
	case errors.Is(err, protocol.ErrInvalidNonce):
		return protocol.ErrorCodeInvalidNonce
	case errors.Is(err, approval.ErrApproverPeerMismatch):
		return protocol.ErrorCodeApproverPeerMismatch
	case errors.Is(err, approval.ErrApproverIdentity):
		return protocol.ErrorCodeApproverIdentityMismatch
	case errors.Is(err, approval.ErrNoPendingApproval):
		return protocol.ErrorCodeNoPendingApproval
	case errors.Is(err, ErrRequestAlreadyActive):
		return protocol.ErrorCodeRequestActive
	case errors.Is(err, daemonbroker.ErrDaemonStopped):
		return protocol.ErrorCodeDaemonStopped
	case errors.Is(err, approval.ErrRequestExpired):
		return protocol.ErrorCodeRequestExpired
	case errors.Is(err, approval.ErrStaleApproval):
		return protocol.ErrorCodeStaleApproval
	case errors.Is(err, peertrust.ErrUntrustedClient):
		return protocol.ErrorCodeUntrustedClient
	case errors.Is(err, context.Canceled):
		return protocol.ErrorCodeContextCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.ErrorCodeContextDeadlineExceeded
	case errors.Is(err, daemonbroker.ErrSecretResolveFailed):
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
