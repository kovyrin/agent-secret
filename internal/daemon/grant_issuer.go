package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

type grantIssuer struct {
	now        func() time.Time
	reusable   *reusableGrantManager
	approver   Approver
	resolver   Resolver
	audit      AuditSink
	fetchLimit int
	stopped    func() bool
}

type ExecGrant struct {
	Env               map[string]string
	SecretAliases     []string
	delivery          grantDelivery
	deliveryExpiresAt time.Time
}

type grantDelivery struct {
	issuer  *grantIssuer
	attempt reusableGrantAttempt
}

type reusableGrantAttempt struct {
	approvalID string
	mutationID string
	expiresAt  time.Time
}

func newGrantIssuer(
	now func() time.Time,
	store *policy.Store,
	cache SecretCache,
	approver Approver,
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

func (g *grantIssuer) deliveryFor(attempt reusableGrantAttempt) grantDelivery {
	return grantDelivery{issuer: g, attempt: attempt}
}

func (d grantDelivery) markPayloadDelivered() error {
	if d.issuer == nil || d.attempt.approvalID == "" {
		return nil
	}
	if err := d.issuer.reusable.ensureApprovalActive(d.attempt.approvalID, d.attempt.expiresAt); err != nil {
		return err
	}
	return d.issuer.reusable.finishPayloadDelivered(d.attempt.approvalID)
}

func (d grantDelivery) markPrePayloadFailure() {
	if d.issuer == nil {
		return
	}
	d.issuer.reusable.finishPrePayloadFailure(d.attempt.approvalID)
}

func (d grantDelivery) rollback() {
	if d.issuer == nil {
		return
	}
	if d.attempt.mutationID != "" {
		d.issuer.reusable.rollbackApproval(d.attempt.mutationID)
		return
	}
	d.markPrePayloadFailure()
}

func (d grantDelivery) approvalID() string {
	return d.attempt.approvalID
}

func (d grantDelivery) expiresAt() time.Time {
	return d.attempt.expiresAt
}

func (g *grantIssuer) issue(
	ctx context.Context,
	requestID string,
	nonce string,
	req request.ExecRequest,
) (ExecGrant, error) {
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}

	grant, err := g.issueReusableGrant(ctx, req)
	if err != nil {
		return ExecGrant{}, g.requestError(ctx, req, err)
	}
	if grant.Env == nil {
		grant, err = g.freshGrant(ctx, requestID, nonce, req)
		if err != nil {
			return ExecGrant{}, g.requestError(ctx, req, err)
		}
	}
	if err := g.ensureGrantStillActive(ctx, req, grant.delivery.approvalID(), grant.delivery.expiresAt()); err != nil {
		grant.delivery.rollback()
		return ExecGrant{}, err
	}
	grant.deliveryExpiresAt = grantDeliveryExpiresAt(req, grant.delivery.expiresAt())

	event := audit.FromExecRequest(audit.EventCommandStarting, requestID, req)
	if err := g.recordRequiredAudit(ctx, event); err != nil {
		grant.delivery.rollback()
		return ExecGrant{}, err
	}
	if err := g.ensureGrantStillActive(ctx, req, grant.delivery.approvalID(), grant.delivery.expiresAt()); err != nil {
		grant.delivery.rollback()
		return ExecGrant{}, err
	}

	return grant, nil
}

func (g *grantIssuer) ensureRequestActive(ctx context.Context, req request.ExecRequest) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), ErrDaemonStopped) {
			return ErrDaemonStopped
		}
		if errors.Is(err, context.DeadlineExceeded) && req.Expired(g.now()) {
			return ErrRequestExpired
		}
		return err
	}
	if g.stopped() {
		return ErrDaemonStopped
	}
	if req.Expired(g.now()) {
		return ErrRequestExpired
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
	if errors.Is(err, ErrApprovalDenied) || errors.Is(err, ErrRequestExpired) {
		return err
	}
	if activeErr := g.ensureRequestActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, ErrRequestExpired) {
			return activeErr
		}
	}
	return err
}

func (g *grantIssuer) issueReusableGrant(ctx context.Context, req request.ExecRequest) (ExecGrant, error) {
	approval, err := g.reusable.reserve(ctx, req, g.audit)
	if err != nil {
		return ExecGrant{}, err
	}
	if approval.ID == "" {
		return ExecGrant{}, nil
	}
	delivery := g.deliveryFor(reusableGrantAttempt{
		approvalID: approval.ID,
		mutationID: reusableMutationID(req.ForceRefresh, approval.ID),
		expiresAt:  approval.ExpiresAt,
	})
	delivered := false
	defer func() {
		if !delivered {
			delivery.markPrePayloadFailure()
		}
	}()
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		return ExecGrant{}, err
	}

	var values map[string]string
	if req.ForceRefresh {
		refValues, err := g.resolveReusableRefresh(ctx, req)
		if err != nil {
			return ExecGrant{}, err
		}
		values, err = g.refreshedReusableValues(ctx, approval, req, refValues)
		if err != nil {
			return ExecGrant{}, err
		}
	} else {
		values, err = g.reusable.cachedValues(approval.ID, req.Secrets)
		if err != nil {
			return ExecGrant{}, err
		}
	}
	if err := g.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt); err != nil {
		return ExecGrant{}, err
	}

	delivered = true
	return ExecGrant{
		Env:           values,
		SecretAliases: aliases(req.Secrets),
		delivery:      delivery,
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
	requestID string,
	nonce string,
	req request.ExecRequest,
) (ExecGrant, error) {
	if err := g.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalRequested, requestID, req)); err != nil {
		return ExecGrant{}, err
	}
	decision, err := g.approver.ApproveExec(ctx, requestID, nonce, req)
	if err != nil {
		if auditErr := g.recordApprovalError(ctx, requestID, req, err); auditErr != nil {
			return ExecGrant{}, auditErr
		}
		return ExecGrant{}, err
	}
	if !decision.Approved {
		if err := g.recordApprovalDenied(ctx, requestID, req); err != nil {
			return ExecGrant{}, err
		}
		return ExecGrant{}, ErrApprovalDenied
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}
	if err := g.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalGranted, requestID, req)); err != nil {
		return ExecGrant{}, err
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}

	refValues, err := g.resolveUniqueRefs(ctx, requestID, req)
	if err != nil {
		return ExecGrant{}, g.requestError(ctx, req, err)
	}
	if err := g.ensureRequestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}
	values := fanoutValues(req.Secrets, refValues)

	approvalID, approvalExpiresAt, err := g.reusable.createGrant(req, decision, refValues)
	if err != nil {
		return ExecGrant{}, err
	}

	return ExecGrant{
		Env:           values,
		SecretAliases: aliases(req.Secrets),
		delivery: g.deliveryFor(reusableGrantAttempt{
			approvalID: approvalID,
			mutationID: approvalID,
			expiresAt:  approvalExpiresAt,
		}),
	}, nil
}

func grantDeliveryExpiresAt(req request.ExecRequest, approvalExpiresAt time.Time) time.Time {
	if !approvalExpiresAt.IsZero() && approvalExpiresAt.Before(req.ExpiresAt) {
		return approvalExpiresAt
	}
	return req.ExpiresAt
}

func reusableMutationID(mutated bool, approvalID string) string {
	if !mutated {
		return ""
	}
	return approvalID
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
	case errors.Is(err, ErrApprovalDenied):
		return g.recordApprovalDenied(ctx, requestID, req)
	case errors.Is(err, ErrRequestExpired):
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
