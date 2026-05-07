package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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
	clientValidator         peertrust.ClientValidator
	onePasswordCheck        func(context.Context, string) error
	selfCheck               func() error
	maxFrameBytes           int64
	readTimeout             time.Duration
	now                     func() time.Time
	beforeRead              func(time.Duration)
	beforeExecResponseWrite func()
	listenUnix              func(string) (unixListener, error)
	retireMu                sync.Mutex
	retireAfterActive       bool
	stopOnce                sync.Once
	stop                    chan struct{}
}

type ServerOptions struct {
	Broker                  *daemonbroker.Broker
	Approvals               approval.ApprovalEndpoint
	Validator               PeerValidator
	ClientValidator         peertrust.ClientValidator
	OnePasswordCheck        func(context.Context, string) error
	SelfCheck               func() error
	MaxFrameBytes           int64
	ReadTimeout             time.Duration
	now                     func() time.Time
	beforeRead              func(time.Duration)
	beforeExecResponseWrite func()
}

const DefaultProtocolReadTimeout = 30 * time.Second

var (
	ErrRequestAlreadyActive        = errors.New("connection already has an active exec request")
	ErrOnePasswordCheckUnavailable = errors.New("1Password desktop integration check unavailable")
	ErrOnePasswordAccountRequired  = errors.New("1Password account is required")
	errClientValidatorRequired     = errors.New("client validator is required")
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

func (s *connectionState) setApprovalDecisionReadTimeout(timeout time.Duration) {
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
	clientValidator := opts.ClientValidator
	if clientValidator == nil {
		return nil, errClientValidatorRequired
	}
	onePasswordCheck := opts.OnePasswordCheck
	if onePasswordCheck == nil {
		onePasswordCheck = func(context.Context, string) error { return ErrOnePasswordCheckUnavailable }
	}
	maxFrameBytes := opts.MaxFrameBytes
	if maxFrameBytes <= 0 {
		maxFrameBytes = protocol.DefaultMaxProtocolFrameBytes
	}
	readTimeout := opts.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultProtocolReadTimeout
	}
	now := opts.now
	if now == nil {
		now = time.Now
	}
	return &Server{
		broker:                  opts.Broker,
		approvals:               opts.Approvals,
		validator:               validator,
		clientValidator:         clientValidator,
		onePasswordCheck:        onePasswordCheck,
		selfCheck:               opts.SelfCheck,
		maxFrameBytes:           maxFrameBytes,
		readTimeout:             readTimeout,
		now:                     now,
		beforeRead:              opts.beforeRead,
		beforeExecResponseWrite: opts.beforeExecResponseWrite,
		listenUnix:              listenUnix,
		stop:                    make(chan struct{}),
	}, nil
}

type unixListener interface {
	AcceptUnix() (*net.UnixConn, error)
	Close() error
}

func listenUnix(path string) (unixListener, error) {
	return socket.ListenUnix(path)
}

func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	listener, err := s.listenUnix(path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = os.Remove(path) }()
	return s.Serve(ctx, listener)
}

func (s *Server) Serve(ctx context.Context, listener unixListener) error {
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

func (s *Server) retireIfExecutableChanged(ctx context.Context, encoder *json.Encoder, env protocol.Envelope) bool {
	if s.selfCheck == nil || s.stopped() || !checksExecutableIdentity(env.Type) {
		return false
	}
	if err := s.selfCheck(); err == nil {
		return false
	} else {
		s.markRetireAfterActive()
		if s.broker.ActiveCount() == 0 {
			s.stopForExecutableChange(ctx)
		}
		stoppedErr := fmt.Errorf("%w: %w", daemonbroker.ErrDaemonStopped, err)
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeDaemonStopped, stoppedErr)
		return true
	}
}

func checksExecutableIdentity(messageType protocol.MessageType) bool {
	//nolint:exhaustive // Only new foreground work should trigger daemon executable self-checks.
	switch messageType {
	case protocol.TypeDaemonStatus, protocol.TypeOnePasswordStatus, protocol.TypeRequestExec, protocol.TypeItemDescribe:
		return true
	default:
		return false
	}
}

func (s *Server) markRetireAfterActive() {
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	s.retireAfterActive = true
}

func (s *Server) stopIfRetiredAndIdle(ctx context.Context) {
	s.retireMu.Lock()
	retire := s.retireAfterActive
	s.retireMu.Unlock()
	if !retire || s.stopped() || s.broker.ActiveCount() != 0 {
		return
	}
	s.stopForExecutableChange(ctx)
}

func (s *Server) stopForExecutableChange(ctx context.Context) {
	s.stopWithAudit(ctx, audit.Event{
		Type:      audit.EventDaemonStop,
		ErrorCode: audit.ErrorCode(protocol.ErrorCodeDaemonStopped),
	})
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
				s.stopIfRetiredAndIdle(ctx)
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
		if s.retireIfExecutableChanged(ctx, encoder, env) {
			return
		}
		if s.stopped() && env.Type != protocol.TypeDaemonStatus {
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(daemonbroker.ErrDaemonStopped), daemonbroker.ErrDaemonStopped)
			return
		}

		state.resetReadTimeout()

		action := s.dispatchClientEnvelope(ctx, conn, encoder, env, &state)
		if action.closeConnection {
			return
		}
		if !action.accepted {
			continue
		}
		action.apply(&state)
	}
}

type connectionDispatchAction struct {
	accepted                    bool
	closeConnection             bool
	approvalDecisionReadTimeout time.Duration
	beginExecRequestID          string
	markStarted                 bool
	markCompleted               bool
}

func (a connectionDispatchAction) apply(state *connectionState) {
	if a.approvalDecisionReadTimeout > 0 {
		state.setApprovalDecisionReadTimeout(a.approvalDecisionReadTimeout)
	}
	if a.beginExecRequestID != "" {
		state.beginExec(a.beginExecRequestID)
	}
	if a.markStarted {
		state.markStarted()
	}
	if a.markCompleted {
		state.markCompleted()
	}
}

func (s *Server) dispatchClientEnvelope(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
	state *connectionState,
) connectionDispatchAction {
	//nolint:exhaustive // Response envelopes are invalid client requests; default rejects them with unknown request types.
	switch env.Type {
	case protocol.TypeDaemonStatus:
		s.handleDaemonStatus(encoder, env)
		return connectionDispatchAction{accepted: true}
	case protocol.TypeOnePasswordStatus:
		s.handleOnePasswordStatus(ctx, conn, encoder, env)
		return connectionDispatchAction{accepted: true}
	case protocol.TypeDaemonStop:
		return connectionDispatchAction{accepted: true, closeConnection: s.handleDaemonStop(ctx, conn, encoder, env)}
	case protocol.TypeApprovalPending:
		payload, ok := s.handleApprovalPending(ctx, conn, encoder, env)
		if !ok {
			return connectionDispatchAction{}
		}
		return connectionDispatchAction{
			accepted:                    true,
			approvalDecisionReadTimeout: s.approvalDecisionReadTimeout(payload.ExpiresAt),
		}
	case protocol.TypeApprovalDecision:
		s.handleApprovalDecision(ctx, conn, encoder, env)
		return connectionDispatchAction{accepted: true}
	case protocol.TypeRequestExec:
		if state.hasActiveRequest() {
			_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(ErrRequestAlreadyActive), ErrRequestAlreadyActive)
			return connectionDispatchAction{}
		}
		requestID := s.handleRequestExec(ctx, conn, encoder, env)
		return connectionDispatchAction{accepted: requestID != "", beginExecRequestID: requestID}
	case protocol.TypeItemDescribe:
		s.handleItemDescribe(ctx, conn, encoder, env)
		return connectionDispatchAction{accepted: true}
	case protocol.TypeCommandStarted:
		if !s.lifecycleRequestMatchesConnection(encoder, env, state) {
			return connectionDispatchAction{}
		}
		return connectionDispatchAction{accepted: s.handleCommandStarted(ctx, conn, encoder, env), markStarted: true}
	case protocol.TypeCommandCompleted:
		if !s.lifecycleRequestMatchesConnection(encoder, env, state) {
			return connectionDispatchAction{}
		}
		return connectionDispatchAction{accepted: s.handleCommandCompleted(ctx, conn, encoder, env), markCompleted: true}
	default:
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadType, fmt.Errorf("%w: %s", protocol.ErrProtocolType, env.Type))
		return connectionDispatchAction{}
	}
}

func (s *Server) handleApprovalDecision(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) {
	if s.approvals == nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeApprovalUnavailable, approval.ErrUnavailable)
		return
	}
	payload, err := protocol.DecodeRequiredPayload[approval.ApprovalDecisionPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadApprovalDecision, err)
		return
	}
	peer, err := s.peerInfo(conn)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodePeerRejected, err)
		return
	}
	if err := s.approvals.SubmitDecision(ctx, peer, payload); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return
	}
	_ = writeOK(encoder, env.Correlation(), nil)
}

func (s *Server) handleItemDescribe(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return
	}
	req, err := protocol.DecodeRequiredPayload[request.ItemDescribeRequest](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return
	}
	req = req.WithReceiptTime(s.broker.Now())
	if err := req.ValidateForDaemon(); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return
	}
	payload, err := s.broker.HandleItemDescribe(ctx, env.Correlation(), req)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return
	}
	_ = writeOK(encoder, env.Correlation(), payload)
}

func (s *Server) handleDaemonStatus(encoder *json.Encoder, env protocol.Envelope) {
	_ = writeOK(encoder, env.Correlation(), protocol.StatusPayload{PID: os.Getpid()})
}

func (s *Server) handleOnePasswordStatus(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env protocol.Envelope,
) {
	if err := s.validateTrustedClientPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return
	}
	payload, err := protocol.DecodeRequiredPayload[protocol.OnePasswordStatusPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, err)
		return
	}
	if strings.TrimSpace(payload.Account) == "" {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeBadRequest, ErrOnePasswordAccountRequired)
		return
	}
	if err := s.onePasswordCheck(ctx, payload.Account); err != nil {
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
	if err := s.clientValidator.ValidatePeer(peer); err != nil {
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
	delivery, err := s.broker.PrepareExecDelivery(ctx, env.Correlation(), req)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	committed := false
	defer func() {
		if !committed {
			delivery.AbortBeforePayload()
		}
	}()
	if s.beforeExecResponseWrite != nil {
		s.beforeExecResponseWrite()
	}
	clearWriteDeadline, err := s.setExecResponseWriteDeadline(conn, delivery.ExpiresAt())
	if err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	defer clearWriteDeadline()
	if err := delivery.BeforeWrite(); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	if err := writeOK(encoder, env.Correlation(), delivery.Payload()); err != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), codeForError(err), err)
		return ""
	}
	delivery.CommitDelivered()
	committed = true
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
	s.stopIfRetiredAndIdle(ctx)
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
		if err := conn.SetReadDeadline(s.now().Add(timeout)); err != nil {
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
	remaining := expiresAt.Sub(s.now())
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
	return s.clientValidator.ValidatePeer(peer)
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
