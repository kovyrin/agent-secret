package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

type grantIssuer struct {
	now        func() time.Time
	reusable   *reusableGrantManager
	approver   approval.Approver
	resolver   Resolver
	audit      AuditSink
	fetchLimit int
	stopped    func() bool
}

type Grant struct {
	Env              map[string]string
	SecretAliases    []string
	approvalID       string
	payloadExpiresAt time.Time
}

type issuedGrant struct {
	grant    Grant
	delivery grantDelivery
}

type grantDelivery struct {
	approvalID string
	mutationID string
	expiresAt  time.Time
}

func newGrantIssuer(
	now func() time.Time,
	store *policy.Store,
	cache SecretCache,
	approver approval.Approver,
	resolver Resolver,
	audit AuditSink,
	fetchLimit int,
	stopped func() bool,
) *grantIssuer {
	issuer := &grantIssuer{
		now:        now,
		approver:   approver,
		resolver:   resolver,
		audit:      audit,
		fetchLimit: fetchLimit,
		stopped:    stopped,
	}
	issuer.reusable = newReusableGrantManager(now, store, cache, stopped)
	return issuer
}

func (g *grantIssuer) completeDelivery(delivery grantDelivery, result policy.DeliveryResult) error {
	if delivery.approvalID == "" {
		return nil
	}
	if result == policy.DeliveryPayloadDelivered {
		if err := g.reusable.ensureApprovalActive(delivery.approvalID, delivery.expiresAt); err != nil {
			return err
		}
	}
	return g.reusable.finishDelivery(delivery.approvalID, result)
}

func (g *grantIssuer) rollbackDelivery(delivery grantDelivery) {
	if delivery.mutationID != "" {
		g.reusable.rollbackApproval(delivery.mutationID)
		return
	}
	_ = g.completeDelivery(delivery, policy.DeliveryPrePayloadFailure)
}

func (g *grantIssuer) issue(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (issuedGrant, error) {
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return issuedGrant{}, err
	}

	issued, err := g.issueReusableGrant(ctx, req)
	if err != nil {
		return issuedGrant{}, g.requestError(ctx, req, err)
	}
	if issued.grant.Env == nil {
		issued, err = g.freshGrant(ctx, correlation, req)
		if err != nil {
			return issuedGrant{}, g.requestError(ctx, req, err)
		}
	}
	if err := g.ensureGrantStillActive(ctx, req, issued.delivery.approvalID, issued.delivery.expiresAt); err != nil {
		g.rollbackDelivery(issued.delivery)
		return issuedGrant{}, err
	}
	issued.grant.payloadExpiresAt = grantPayloadExpiresAt(req, issued.delivery.expiresAt)

	event := audit.FromExecRequest(audit.EventCommandStarting, correlation.RequestID, req)
	if err := g.recordRequiredAudit(ctx, event); err != nil {
		g.rollbackDelivery(issued.delivery)
		return issuedGrant{}, err
	}
	if err := g.ensureGrantStillActive(ctx, req, issued.delivery.approvalID, issued.delivery.expiresAt); err != nil {
		g.rollbackDelivery(issued.delivery)
		return issuedGrant{}, err
	}

	return issued, nil
}

func (g *grantIssuer) ensureRequestActive(ctx context.Context, req request.ExecRequest) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), ErrDaemonStopped) {
			return ErrDaemonStopped
		}
		if errors.Is(err, context.DeadlineExceeded) && req.Expired(g.now()) {
			return approval.ErrRequestExpired
		}
		return err
	}
	if g.stopped() {
		return ErrDaemonStopped
	}
	if req.Expired(g.now()) {
		return approval.ErrRequestExpired
	}
	return nil
}

func (g *grantIssuer) ensureGrantStillActive(
	ctx context.Context,
	req request.ExecRequest,
	approvalID string,
	approvalExpiresAt time.Time,
) error {
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return err
	}
	return g.reusable.ensureApprovalActive(approvalID, approvalExpiresAt)
}

func (g *grantIssuer) clearReusableGrants() {
	g.reusable.clear()
}

func (g *grantIssuer) requestError(ctx context.Context, req request.ExecRequest, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, approval.ErrApprovalDenied) || errors.Is(err, approval.ErrRequestExpired) {
		return err
	}
	if activeErr := g.ensureRequestActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, approval.ErrRequestExpired) {
			return activeErr
		}
	}
	return err
}

func (g *grantIssuer) issueReusableGrant(ctx context.Context, req request.ExecRequest) (issuedGrant, error) {
	approval, err := g.reusable.reserve(ctx, req, g.audit)
	if err != nil {
		return issuedGrant{}, err
	}
	if approval.ID == "" {
		return issuedGrant{}, nil
	}
	mutationID := ""
	if req.ForceRefresh {
		mutationID = approval.ID
	}
	delivery := grantDelivery{
		approvalID: approval.ID,
		mutationID: mutationID,
		expiresAt:  approval.ExpiresAt,
	}
	delivered := false
	defer func() {
		if !delivered {
			_ = g.completeDelivery(delivery, policy.DeliveryPrePayloadFailure)
		}
	}()
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		return issuedGrant{}, err
	}

	var values map[string]string
	if req.ForceRefresh {
		refValues, err := g.resolveReusableRefresh(ctx, req)
		if err != nil {
			return issuedGrant{}, err
		}
		values, err = g.refreshedReusableValues(ctx, approval, req, refValues)
		if err != nil {
			return issuedGrant{}, err
		}
	} else {
		values, err = g.reusable.cachedValues(approval.ID, req.Secrets)
		if err != nil {
			return issuedGrant{}, err
		}
	}
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		return issuedGrant{}, err
	}

	delivered = true
	return issuedGrant{
		grant: Grant{
			Env:           values,
			SecretAliases: request.SecretAliases(req.Secrets),
			approvalID:    approval.ID,
		},
		delivery: delivery,
	}, nil
}

func (g *grantIssuer) resolveReusableRefresh(
	ctx context.Context,
	req request.ExecRequest,
) (map[secretIdentity]string, error) {
	refValues, err := g.resolveUniqueRefs(ctx, "", req)
	if err != nil {
		return nil, g.requestError(ctx, req, err)
	}
	return refValues, nil
}

func (g *grantIssuer) recordReusableRefresh(
	ctx context.Context,
	req request.ExecRequest,
	approval policy.ReusableApproval,
) error {
	event := audit.FromExecRequest(audit.EventApprovalRefreshed, "", req)
	event.ApprovalID = approval.ID
	return g.recordRequiredAudit(ctx, event)
}

func (g *grantIssuer) refreshedReusableValues(
	ctx context.Context,
	approval policy.ReusableApproval,
	req request.ExecRequest,
	refValues map[secretIdentity]string,
) (map[string]string, error) {
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		return nil, err
	}
	values := fanoutValues(req.Secrets, refValues)
	if err := g.reusable.cacheResolvedValues(approval.ID, approval.ExpiresAt, refValues); err != nil {
		g.reusable.rollbackApproval(approval.ID)
		return nil, err
	}
	if err := g.recordReusableRefresh(ctx, req, approval); err != nil {
		g.reusable.rollbackApproval(approval.ID)
		return nil, err
	}
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		g.reusable.rollbackApproval(approval.ID)
		return nil, err
	}
	return values, nil
}

func (g *grantIssuer) preflightAudit(ctx context.Context) error {
	if err := g.audit.Preflight(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}
	return nil
}

func (g *grantIssuer) freshGrant(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (issuedGrant, error) {
	if err := g.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalRequested, correlation.RequestID, req)); err != nil {
		return issuedGrant{}, err
	}
	decision, err := g.approver.ApproveExec(ctx, correlation, req)
	if err != nil {
		if auditErr := g.recordApprovalError(ctx, correlation.RequestID, req, err); auditErr != nil {
			return issuedGrant{}, auditErr
		}
		return issuedGrant{}, err
	}
	if !decision.Approved {
		if err := g.recordApprovalDenied(ctx, correlation.RequestID, req); err != nil {
			return issuedGrant{}, err
		}
		return issuedGrant{}, approval.ErrApprovalDenied
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return issuedGrant{}, err
	}
	if err := g.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalGranted, correlation.RequestID, req)); err != nil {
		return issuedGrant{}, err
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return issuedGrant{}, err
	}

	refValues, err := g.resolveUniqueRefs(ctx, correlation.RequestID, req)
	if err != nil {
		return issuedGrant{}, g.requestError(ctx, req, err)
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return issuedGrant{}, err
	}
	values := fanoutValues(req.Secrets, refValues)

	approvalID, approvalExpiresAt, err := g.reusable.createGrant(req, decision, refValues)
	if err != nil {
		return issuedGrant{}, err
	}

	delivery := grantDelivery{
		approvalID: approvalID,
		mutationID: approvalID,
		expiresAt:  approvalExpiresAt,
	}
	return issuedGrant{
		grant: Grant{
			Env:           values,
			SecretAliases: request.SecretAliases(req.Secrets),
			approvalID:    approvalID,
		},
		delivery: delivery,
	}, nil
}

func grantPayloadExpiresAt(req request.ExecRequest, approvalExpiresAt time.Time) time.Time {
	if !approvalExpiresAt.IsZero() && approvalExpiresAt.Before(req.ExpiresAt) {
		return approvalExpiresAt
	}
	return req.ExpiresAt
}

func (g *grantIssuer) resolveUniqueRefs(
	ctx context.Context,
	requestID string,
	req request.ExecRequest,
) (map[secretIdentity]string, error) {
	secrets := req.Secrets
	identities := uniqueSecretIdentities(secrets)
	type result struct {
		identity secretIdentity
		value    string
		err      error
	}

	if err := g.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventSecretFetchStarted, requestID, req)); err != nil {
		return nil, err
	}

	fetchCtx, cancelFetches := context.WithCancel(ctx)
	defer cancelFetches()

	sem := make(chan struct{}, g.fetchLimit)
	results := make(chan result, len(identities))
	for _, identity := range identities {
		go func(identity secretIdentity) {
			select {
			case sem <- struct{}{}:
			case <-fetchCtx.Done():
				return
			}
			defer func() { <-sem }()

			value, err := g.resolver.Resolve(fetchCtx, identity.ref, identity.account)
			select {
			case results <- result{identity: identity, value: value, err: err}:
			case <-fetchCtx.Done():
			}
		}(identity)
	}

	resolved := make(map[secretIdentity]string, len(identities))
	pending := make(map[secretIdentity]struct{}, len(identities))
	for _, identity := range identities {
		pending[identity] = struct{}{}
	}
	for remaining := len(identities); remaining > 0; remaining-- {
		var got result
		select {
		case got = <-results:
			delete(pending, got.identity)
		case <-fetchCtx.Done():
			err := contextCause(fetchCtx)
			if auditErr := g.recordSecretFetchFailedForIdentities(
				ctx,
				requestID,
				secrets,
				pendingIdentities(identities, pending),
				err,
			); auditErr != nil {
				return nil, auditErr
			}
			return nil, fmt.Errorf("%w: resolve approved ref: %w", ErrSecretResolveFailed, err)
		}

		if got.err != nil {
			cancelFetches()
			if err := g.recordSecretFetchFailed(ctx, requestID, secrets, got.identity, got.err); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: resolve approved ref: %w", ErrSecretResolveFailed, got.err)
		}
		resolved[got.identity] = got.value
	}

	return resolved, nil
}

func (g *grantIssuer) recordRequiredAudit(ctx context.Context, event audit.Event) error {
	if err := g.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}
	return nil
}

func (g *grantIssuer) recordApprovalError(
	ctx context.Context,
	requestID string,
	req request.ExecRequest,
	err error,
) error {
	switch {
	case errors.Is(err, approval.ErrApprovalDenied):
		return g.recordApprovalDenied(ctx, requestID, req)
	case errors.Is(err, approval.ErrRequestExpired):
		event := audit.FromExecRequest(audit.EventApprovalTimedOut, requestID, req)
		event.ErrorCode = auditErrorCode(protocol.ErrorCodeRequestExpired)
		auditCtx, cancel := terminalAuditContext(ctx)
		defer cancel()
		return g.recordRequiredAudit(auditCtx, event)
	default:
		return nil
	}
}

func (g *grantIssuer) recordApprovalDenied(ctx context.Context, requestID string, req request.ExecRequest) error {
	event := audit.FromExecRequest(audit.EventApprovalDenied, requestID, req)
	event.ErrorCode = auditErrorCode(protocol.ErrorCodeApprovalDenied)
	auditCtx, cancel := terminalAuditContext(ctx)
	defer cancel()
	return g.recordRequiredAudit(auditCtx, event)
}

func (g *grantIssuer) recordSecretFetchFailed(
	ctx context.Context,
	requestID string,
	secrets []request.Secret,
	identity secretIdentity,
	err error,
) error {
	return g.recordSecretFetchFailureEvent(ctx, requestID, auditRefsForIdentity(secrets, identity), err)
}

func (g *grantIssuer) recordSecretFetchFailedForIdentities(
	ctx context.Context,
	requestID string,
	secrets []request.Secret,
	identities []secretIdentity,
	err error,
) error {
	return g.recordSecretFetchFailureEvent(ctx, requestID, auditRefsForIdentities(secrets, identities), err)
}

func (g *grantIssuer) recordSecretFetchFailureEvent(
	ctx context.Context,
	requestID string,
	refs []audit.SecretRef,
	err error,
) error {
	event := audit.Event{
		Type:       audit.EventSecretFetchFailed,
		RequestID:  requestID,
		SecretRefs: refs,
		ErrorCode:  auditErrorCode(secretFetchErrorCode(err)),
	}
	auditCtx, cancel := terminalAuditContext(ctx)
	defer cancel()
	return g.recordRequiredAudit(auditCtx, event)
}
