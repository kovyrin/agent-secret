package broker

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/gcpcompat"
	"github.com/kovyrin/agent-secret/internal/request"
)

type unavailableGCPTokenMinter struct{}

func (unavailableGCPTokenMinter) MintAccessToken(context.Context, GCPMintRequest) (gcpcompat.Token, error) {
	return gcpcompat.Token{}, ErrNoGCPTokenMinter
}

func (a gcpSessionCommandAudit) SessionAuditIDValue() string {
	return a.SessionAuditID
}

func (a gcpSessionCommandAudit) ReasonValue() string {
	return a.Reason
}

func (a gcpSessionCommandAudit) ProfileNameValue() string {
	return a.ProfileName
}

func (a gcpSessionCommandAudit) ProjectRootValue() string {
	return a.ProjectRoot
}

func (a gcpSessionCommandAudit) AccessValue() request.GCPAccess {
	return a.Access
}

func (a gcpSessionCommandAudit) CommandValue() []string {
	return slices.Clone(a.Command)
}

func (a gcpSessionCommandAudit) ResolvedExecutableValue() string {
	return a.ResolvedExecutable
}

func (a gcpSessionCommandAudit) CWDValue() string {
	return a.CWD
}

func (a gcpSessionCommandAudit) DeliveryModeValue() string {
	return a.DeliveryMode
}

type GCPExecDelivery struct {
	broker       *Broker
	cancelExec   context.CancelFunc
	correlation  protocol.Correlation
	req          request.GCPExecRequest
	payload      protocol.GCPCommandResponsePayload
	cleanup      func()
	finalizeOnce sync.Once
}

func (b *Broker) PrepareGCPExecDelivery(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPExecRequest,
) (*GCPExecDelivery, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return nil, protocol.ErrInvalidNonce
	}
	if b.stopped() {
		return nil, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return nil, err
	}
	if req.Expired(b.now()) {
		return nil, approval.ErrRequestExpired
	}
	execCtx, cancelExec := b.requestContext(ctx, req.ExpiresAt)
	if err := recordRequiredAudit(execCtx, b.audit, audit.FromGCPExecRequest(audit.EventApprovalRequested, correlation.RequestID, req)); err != nil {
		cancelExec()
		return nil, err
	}
	decision, err := b.approver.Approve(execCtx, approval.NewGCPExecPayload(correlation, req))
	if err != nil {
		cancelExec()
		return nil, b.gcpRequestError(execCtx, req, err)
	}
	if !decision.Approved {
		event := audit.FromGCPExecRequest(audit.EventApprovalDenied, correlation.RequestID, req)
		event.ErrorCode = auditErrorCode(protocol.ErrorCodeApprovalDenied)
		if auditErr := recordTerminalRequiredAudit(ctx, b.audit, event); auditErr != nil {
			cancelExec()
			return nil, auditErr
		}
		cancelExec()
		return nil, approval.DenialError(decision.DenialReason)
	}
	if err := b.ensureGCPExecActive(execCtx, req); err != nil {
		cancelExec()
		return nil, err
	}
	if err := recordRequiredAudit(execCtx, b.audit, audit.FromGCPExecRequest(audit.EventApprovalGranted, correlation.RequestID, req)); err != nil {
		cancelExec()
		return nil, err
	}
	delivery, err := b.prepareGCPTokenDelivery(execCtx, correlation.RequestID, req.Access(), req.Reason, req.TTL, req.ExpiresAt)
	if err != nil {
		cancelExec()
		return nil, b.gcpRequestError(execCtx, req, err)
	}
	if err := b.activateGCPExec(correlation, req, delivery.Cleanup); err != nil {
		delivery.Cleanup()
		cancelExec()
		return nil, err
	}
	return &GCPExecDelivery{
		broker:      b,
		cancelExec:  cancelExec,
		correlation: correlation,
		req:         req,
		payload: protocol.GCPCommandResponsePayload{
			Env:          delivery.Env,
			DeliveryMode: req.DeliveryMode,
			ExpiresAt:    delivery.ExpiresAt,
		},
		cleanup: delivery.Cleanup,
	}, nil
}

func (d *GCPExecDelivery) Payload() protocol.GCPCommandResponsePayload {
	return d.payload
}

func (d *GCPExecDelivery) ExpiresAt() time.Time {
	return d.payload.ExpiresAt
}

func (d *GCPExecDelivery) CommitDelivered() {
	d.finalizeOnce.Do(func() {
		d.cancelExec()
	})
}

func (d *GCPExecDelivery) AbortBeforePayload() {
	d.finalizeOnce.Do(func() {
		d.broker.deactivateExec(d.correlation)
		if d.cleanup != nil {
			d.cleanup()
		}
		d.cancelExec()
	})
}

func (b *Broker) CreateGCPSession(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPSessionCreateRequest,
	handle string,
) (protocol.GCPSessionCreateResponsePayload, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return protocol.GCPSessionCreateResponsePayload{}, protocol.ErrInvalidNonce
	}
	if handle == "" {
		return protocol.GCPSessionCreateResponsePayload{}, fmt.Errorf("%w: generated session handle is required", request.ErrInvalidGCPSession)
	}
	if b.stopped() {
		return protocol.GCPSessionCreateResponsePayload{}, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.GCPSessionCreateResponsePayload{}, err
	}
	if req.Expired(b.now()) {
		return protocol.GCPSessionCreateResponsePayload{}, approval.ErrRequestExpired
	}
	sessionCtx, cancelSession := b.requestContext(ctx, req.ExpiresAt)
	defer cancelSession()

	if err := recordRequiredAudit(sessionCtx, b.audit, audit.FromGCPSessionCreateRequest(audit.EventApprovalRequested, correlation.RequestID, req, "")); err != nil {
		return protocol.GCPSessionCreateResponsePayload{}, err
	}
	decision, err := b.approver.Approve(sessionCtx, approval.NewGCPSessionCreatePayload(correlation, req, request.GCPSessionHandleAuditID(handle)))
	if err != nil {
		return protocol.GCPSessionCreateResponsePayload{}, err
	}
	if !decision.Approved {
		event := audit.FromGCPSessionCreateRequest(audit.EventApprovalDenied, correlation.RequestID, req, "")
		event.ErrorCode = auditErrorCode(protocol.ErrorCodeApprovalDenied)
		if auditErr := recordTerminalRequiredAudit(ctx, b.audit, event); auditErr != nil {
			return protocol.GCPSessionCreateResponsePayload{}, auditErr
		}
		return protocol.GCPSessionCreateResponsePayload{}, approval.DenialError(decision.DenialReason)
	}
	auditID := request.GCPSessionHandleAuditID(handle)
	session := &gcpSession{
		handle:          handle,
		auditID:         auditID,
		req:             req,
		expiresAt:       req.ExpiresAt,
		remainingStarts: req.MaxCommandStarts,
	}
	b.mu.Lock()
	if b.stopped() {
		b.mu.Unlock()
		return protocol.GCPSessionCreateResponsePayload{}, ErrDaemonStopped
	}
	b.gcpSessions[handle] = session
	b.mu.Unlock()
	if err := recordRequiredAudit(sessionCtx, b.audit, audit.FromGCPSessionCreateRequest(audit.EventGCPSessionCreated, correlation.RequestID, req, auditID)); err != nil {
		b.destroyGCPSessionByHandle(handle)
		return protocol.GCPSessionCreateResponsePayload{}, err
	}
	return protocol.GCPSessionCreateResponsePayload{
		SessionHandle:          handle,
		SessionAuditID:         auditID,
		ExpiresAt:              req.ExpiresAt,
		RemainingCommandStarts: req.MaxCommandStarts,
	}, nil
}

func (b *Broker) PrepareGCPSessionCommandDelivery(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.GCPSessionUseRequest,
) (*GCPExecDelivery, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return nil, protocol.ErrInvalidNonce
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return nil, err
	}
	session, err := b.reserveGCPSessionCommand(req)
	if err != nil {
		return nil, err
	}
	commandAudit := session.commandAudit(req)
	token, reused, err := b.sessionTokenForCommand(ctx, correlation.RequestID, session)
	if err != nil {
		b.restoreGCPSessionStart(session.handle)
		return nil, err
	}
	if reused {
		if err := recordRequiredAudit(ctx, b.audit, audit.FromGCPSessionCommand(audit.EventGCPTokenReused, correlation.RequestID, commandAudit)); err != nil {
			b.restoreGCPSessionStart(session.handle)
			return nil, err
		}
	}
	if err := b.activateGCPSessionUse(correlation, commandAudit, token.env, token.expiresAt); err != nil {
		b.restoreGCPSessionStart(session.handle)
		return nil, err
	}
	return &GCPExecDelivery{
		broker:      b,
		cancelExec:  func() {},
		correlation: correlation,
		req: request.GCPExecRequest{
			Reason:             commandAudit.Reason,
			Command:            slices.Clone(commandAudit.Command),
			ResolvedExecutable: commandAudit.ResolvedExecutable,
			CWD:                commandAudit.CWD,
			GoogleAccount:      commandAudit.Access.GoogleAccount,
			Project:            commandAudit.Access.Project,
			ServiceAccount:     commandAudit.Access.ServiceAccount,
			Scopes:             slices.Clone(commandAudit.Access.Scopes),
			ProfileName:        commandAudit.ProfileName,
			ConfigRoot:         commandAudit.ProjectRoot,
			DeliveryMode:       commandAudit.DeliveryMode,
			ExpiresAt:          token.expiresAt,
		},
		payload: protocol.GCPCommandResponsePayload{
			Env:          token.env,
			DeliveryMode: commandAudit.DeliveryMode,
			ExpiresAt:    token.expiresAt,
		},
		cleanup: func() { b.restoreGCPSessionStart(session.handle) },
	}, nil
}

func (b *Broker) ListGCPSessions(ctx context.Context, cwd string) (protocol.GCPSessionListResponsePayload, error) {
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.GCPSessionListResponsePayload{}, err
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	sessions := make([]protocol.GCPSessionInfo, 0, len(b.gcpSessions))
	for _, session := range b.gcpSessions {
		if !now.Before(session.expiresAt) {
			continue
		}
		sessions = append(sessions, session.info(now, cwd))
	}
	slices.SortFunc(sessions, func(a, b protocol.GCPSessionInfo) int {
		return strings.Compare(a.SessionAuditID, b.SessionAuditID)
	})
	return protocol.GCPSessionListResponsePayload{Sessions: sessions}, nil
}

func (b *Broker) DestroyGCPSession(ctx context.Context, req request.GCPSessionDestroyRequest) (protocol.GCPSessionDestroyResponsePayload, error) {
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.GCPSessionDestroyResponsePayload{}, err
	}
	session := b.destroyGCPSessionByHandle(req.SessionHandle)
	destroyed := session != nil
	auditID := ""
	if session != nil {
		auditID = session.auditID
	}
	event := audit.Event{
		Type:         audit.EventGCPSessionDestroyed,
		Provider:     "gcp",
		Operation:    "session_destroyed",
		GCPSessionID: auditID,
		CWD:          req.CWD,
	}
	if session != nil {
		event.Reason = session.req.Reason
		event.ProfileName = session.req.ProfileName
		event.Project = session.req.Project
		event.ServiceAccount = session.req.ServiceAccount
		event.GoogleAccount = session.req.GoogleAccount
		event.OAuthScopes = slices.Clone(session.req.Scopes)
	}
	if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
		return protocol.GCPSessionDestroyResponsePayload{}, err
	}
	return protocol.GCPSessionDestroyResponsePayload{Destroyed: destroyed, SessionAuditID: auditID}, nil
}

func (b *Broker) prepareGCPTokenDelivery(
	ctx context.Context,
	requestID string,
	access request.GCPAccess,
	reason string,
	requestedLifetime time.Duration,
	expiresAt time.Time,
) (*gcpcompat.Delivery, error) {
	lifetime := minDuration(requestedLifetime, time.Until(expiresAt))
	if now := b.now(); expiresAt.After(now) {
		lifetime = minDuration(requestedLifetime, expiresAt.Sub(now))
	}
	if lifetime < request.MinRequestTTL {
		return nil, approval.ErrRequestExpired
	}
	if err := recordRequiredAudit(ctx, b.audit, audit.FromGCPTokenMint(audit.EventGCPTokenMintStarted, requestID, access, reason, lifetime, request.GCPDeliveryModeTokenFile, "")); err != nil {
		return nil, err
	}
	token, err := b.gcpMinter.MintAccessToken(ctx, GCPMintRequest{
		GoogleAccount:  access.GoogleAccount,
		Project:        access.Project,
		ServiceAccount: access.ServiceAccount,
		Scopes:         slices.Clone(access.Scopes),
		Lifetime:       lifetime,
		Reason:         reason,
	})
	if err != nil {
		event := audit.FromGCPTokenMint(audit.EventGCPTokenMintFailed, requestID, access, reason, lifetime, request.GCPDeliveryModeTokenFile, "")
		event.ErrorCode = auditErrorCode(protocol.ErrorCodeResolveFailed)
		if auditErr := recordTerminalRequiredAudit(ctx, b.audit, event); auditErr != nil {
			return nil, auditErr
		}
		return nil, fmt.Errorf("%w: %w", ErrNoGCPTokenMinter, err)
	}
	if token.ExpiresAt.IsZero() || token.ExpiresAt.After(expiresAt) {
		token.ExpiresAt = expiresAt
	}
	delivery, err := gcpcompat.PrepareTokenFileDelivery(b.gcpDeliveryBaseDir, access.Project, token)
	if err != nil {
		return nil, err
	}
	if err := recordRequiredAudit(ctx, b.audit, audit.FromGCPTokenMint(audit.EventGCPTokenMintCompleted, requestID, access, reason, lifetime, request.GCPDeliveryModeTokenFile, "")); err != nil {
		delivery.Cleanup()
		return nil, err
	}
	return delivery, nil
}

func (b *Broker) sessionTokenForCommand(ctx context.Context, requestID string, session *gcpSession) (*gcpSessionToken, bool, error) {
	now := b.now()
	if session.token != nil && now.Before(session.token.expiresAt) {
		margin := request.GCPSessionRemainingTokenRefreshMargin(session.token.lifetime)
		if session.token.expiresAt.Sub(now) >= margin {
			return session.token, true, nil
		}
	}
	if session.token != nil {
		session.token.cleanup()
		session.token = nil
	}
	access := session.req.Access()
	lifetime := minDuration(session.req.TTL, session.expiresAt.Sub(now))
	delivery, err := b.prepareGCPTokenDelivery(ctx, requestID, access, session.req.Reason, lifetime, session.expiresAt)
	if err != nil {
		return nil, false, err
	}
	token := &gcpSessionToken{
		env:       delivery.Env,
		expiresAt: delivery.ExpiresAt,
		lifetime:  lifetime,
		cleanup:   delivery.Cleanup,
	}
	session.token = token
	return token, false, nil
}

func (b *Broker) activateGCPExec(correlation protocol.Correlation, req request.GCPExecRequest, cleanup func()) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped() {
		return ErrDaemonStopped
	}
	b.active[correlation.RequestID] = &activeCommand{
		nonce:   correlation.Nonce,
		kind:    activeKindGCPExec,
		gcpReq:  req,
		cleanup: cleanup,
	}
	return nil
}

func (b *Broker) activateGCPSessionUse(
	correlation protocol.Correlation,
	commandAudit gcpSessionCommandAudit,
	env map[string]string,
	expiresAt time.Time,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped() {
		return ErrDaemonStopped
	}
	_ = env
	_ = expiresAt
	b.active[correlation.RequestID] = &activeCommand{
		nonce:   correlation.Nonce,
		kind:    activeKindGCPSessionUse,
		session: &commandAudit,
	}
	return nil
}

func (b *Broker) ensureGCPExecActive(ctx context.Context, req request.GCPExecRequest) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), ErrDaemonStopped) {
			return ErrDaemonStopped
		}
		if errors.Is(err, context.DeadlineExceeded) && req.Expired(b.now()) {
			return approval.ErrRequestExpired
		}
		return err
	}
	if b.stopped() {
		return ErrDaemonStopped
	}
	if req.Expired(b.now()) {
		return approval.ErrRequestExpired
	}
	return nil
}

func (b *Broker) gcpRequestError(ctx context.Context, req request.GCPExecRequest, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, approval.ErrApprovalDenied) || errors.Is(err, approval.ErrRequestExpired) {
		return err
	}
	if activeErr := b.ensureGCPExecActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, approval.ErrRequestExpired) {
			return activeErr
		}
	}
	return err
}

func (b *Broker) reserveGCPSessionCommand(req request.GCPSessionUseRequest) (*gcpSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	session := b.gcpSessions[req.SessionHandle]
	if session == nil {
		return nil, ErrUnknownGCPSession
	}
	now := b.now()
	if !now.Before(session.expiresAt) {
		session.cleanup()
		delete(b.gcpSessions, req.SessionHandle)
		return nil, ErrGCPSessionExpired
	}
	if session.remainingStarts <= 0 {
		return nil, ErrGCPSessionExhausted
	}
	if !isPathWithinRoot(req.CWD, session.req.ProjectRoot) {
		return nil, ErrGCPSessionNotUsableFromCWD
	}
	session.remainingStarts--
	return session, nil
}

func (b *Broker) restoreGCPSessionStart(handle string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if session := b.gcpSessions[handle]; session != nil {
		session.remainingStarts++
	}
}

func (b *Broker) destroyGCPSessionByHandle(handle string) *gcpSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	session := b.gcpSessions[handle]
	if session == nil {
		return nil
	}
	session.cleanup()
	delete(b.gcpSessions, handle)
	return session
}

func (session *gcpSession) cleanup() {
	if session.token != nil {
		session.token.cleanup()
		session.token = nil
	}
}

func (session *gcpSession) commandAudit(req request.GCPSessionUseRequest) gcpSessionCommandAudit {
	return gcpSessionCommandAudit{
		SessionAuditID:     session.auditID,
		Reason:             session.req.Reason,
		ProfileName:        session.req.ProfileName,
		ProjectRoot:        session.req.ProjectRoot,
		Access:             session.req.Access(),
		Command:            slices.Clone(req.Command),
		ResolvedExecutable: req.ResolvedExecutable,
		CWD:                req.CWD,
		DeliveryMode:       session.req.DeliveryMode,
	}
}

func (session *gcpSession) info(now time.Time, cwd string) protocol.GCPSessionInfo {
	remaining := session.expiresAt.Sub(now)
	remaining = max(remaining, 0)
	return protocol.GCPSessionInfo{
		SessionAuditID:         session.auditID,
		ProfileName:            session.req.ProfileName,
		GoogleAccount:          session.req.GoogleAccount,
		Project:                session.req.Project,
		ServiceAccount:         session.req.ServiceAccount,
		Scopes:                 slices.Clone(session.req.Scopes),
		ProjectRoot:            session.req.ProjectRoot,
		Reason:                 session.req.Reason,
		ExpiresAt:              session.expiresAt,
		RemainingTTLMillis:     remaining.Milliseconds(),
		RemainingCommandStarts: session.remainingStarts,
		UsableFromCWD:          cwd == "" || isPathWithinRoot(cwd, session.req.ProjectRoot),
	}
}

func isPathWithinRoot(path string, root string) bool {
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
