package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

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
	stopOnce      sync.Once
	stop          chan struct{}
}

type ServerOptions struct {
	Broker        *Broker
	Approvals     ApprovalEndpoint
	Validator     PeerValidator
	ExecValidator ExecPeerValidator
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
		execValidator = NewTrustedExecutableValidator(DefaultTrustedClientPaths())
	}
	return &Server{
		broker:        opts.Broker,
		approvals:     opts.Approvals,
		validator:     validator,
		execValidator: execValidator,
		stop:          make(chan struct{}),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	listener, err := ListenUnix(path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
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
	s.broker.Stop(ctx)
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer func() { _ = conn.Close() }()
	if err := s.validator.Validate(conn); err != nil {
		_ = writeError(conn, "", "", "peer_rejected", err)
		return
	}

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	activeRequestID := ""
	for {
		var env Envelope
		if err := decoder.Decode(&env); err != nil {
			if activeRequestID != "" {
				s.broker.ClientDisconnected(ctx, activeRequestID)
			}
			return
		}
		if err := validateEnvelope(env); err != nil {
			_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_envelope", err)
			continue
		}

		switch env.Type {
		case TypeDaemonStatus:
			_ = writeOK(encoder, env.RequestID, env.Nonce, StatusPayload{PID: os.Getpid()})
		case TypeDaemonStop:
			_ = writeOK(encoder, env.RequestID, env.Nonce, StatusPayload{PID: os.Getpid()})
			s.Stop(ctx)
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
			_ = writeOK(encoder, payload.RequestID, payload.Nonce, payload)
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
			if requestID := s.handleRequestExec(ctx, conn, encoder, env); requestID != "" {
				activeRequestID = requestID
			}
		case TypeCommandStarted:
			s.handleCommandStarted(ctx, conn, encoder, env)
		case TypeCommandCompleted:
			if s.handleCommandCompleted(ctx, conn, encoder, env) {
				activeRequestID = ""
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
	req, err := DecodePayload[request.ExecRequest](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_request", err)
		return ""
	}
	if err := req.ValidateForDaemon(); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_request", err)
		return ""
	}
	if err := s.validateExecPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return ""
	}
	grant, err := s.broker.HandleExec(ctx, env.RequestID, env.Nonce, req)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return ""
	}
	err = writeOK(encoder, env.RequestID, env.Nonce, ExecResponsePayload{
		Env:           grant.Env,
		SecretAliases: grant.SecretAliases,
	})
	if err == nil {
		_ = s.broker.MarkPayloadDelivered(env.RequestID)
	}
	return env.RequestID
}

func (s *Server) handleCommandStarted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env Envelope,
) {
	payload, err := DecodePayload[CommandStartedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_command_started", err)
		return
	}
	if err := s.validateExecPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return
	}
	if err := s.broker.ReportStarted(ctx, env.RequestID, env.Nonce, payload.ChildPID); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
		return
	}
	_ = writeOK(encoder, env.RequestID, env.Nonce, nil)
}

func (s *Server) handleCommandCompleted(
	ctx context.Context,
	conn *net.UnixConn,
	encoder *json.Encoder,
	env Envelope,
) bool {
	payload, err := DecodePayload[CommandCompletedPayload](env)
	if err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, "bad_command_completed", err)
		return false
	}
	if err := s.validateExecPeer(conn); err != nil {
		_ = writeErrorEncoder(encoder, env.RequestID, env.Nonce, codeForError(err), err)
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

func (s *Server) validateExecPeer(conn *net.UnixConn) error {
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
	case errors.Is(err, ErrNoPendingApproval):
		return "no_pending_approval"
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
