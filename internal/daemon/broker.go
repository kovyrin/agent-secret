package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

var (
	ErrApprovalDenied       = errors.New("approval denied")
	ErrApprovalUnavailable  = errors.New("approval unavailable")
	ErrAuditRequired        = errors.New("audit required")
	ErrInvalidNonce         = errors.New("invalid request nonce")
	ErrMissingCache         = errors.New("approved secret cache entry missing")
	ErrNoResolver           = errors.New("secret resolver unavailable")
	ErrRequestAlreadyActive = errors.New("connection already has an active exec request")
	ErrDaemonStopped        = errors.New("daemon stopped")
	ErrRequestExpired       = errors.New("request expired")
	ErrUnknownRequest       = errors.New("unknown request")
)

type Approver interface {
	ApproveExec(ctx context.Context, requestID string, nonce string, req request.ExecRequest) (ApprovalDecision, error)
}

type ApprovalDecision struct {
	Approved     bool
	Reusable     bool
	ReusableUses int
}

type Resolver interface {
	Resolve(ctx context.Context, ref string, account string) (string, error)
}

type AuditSink interface {
	policy.ReuseAuditSink
	Preflight(ctx context.Context) error
	Record(ctx context.Context, event audit.Event) error
}

type SecretCache interface {
	Put(scopeID string, ref string, account string, value string) error
	Get(scopeID string, ref string, account string) (string, bool)
	ClearScope(scopeID string)
	Clear()
}

type Broker struct {
	mu         sync.Mutex
	now        func() time.Time
	reusable   *reusableGrantManager
	approver   Approver
	resolver   Resolver
	audit      AuditSink
	fetchLimit int
	active     map[string]*activeExec
	stopOnce   sync.Once
	stop       chan struct{}
}

type ExecGrant struct {
	Env                map[string]string
	SecretAliases      []string
	ApprovalID         string
	reusableMutationID string
	approvalExpiresAt  time.Time
	deliveryExpiresAt  time.Time
}

type execDelivery struct {
	broker    *Broker
	requestID string
	payload   protocol.ExecResponsePayload
	expiresAt time.Time
}

type activeExec struct {
	nonce             string
	req               request.ExecRequest
	approvalID        string
	payloadDelivered  bool
	started           bool
	childPID          *int
	approvalExpiresAt time.Time
}

type BrokerOptions struct {
	Now        func() time.Time
	Store      *policy.Store
	Cache      SecretCache
	Approver   Approver
	Resolver   Resolver
	Audit      AuditSink
	FetchLimit int
}

func NewBroker(opts BrokerOptions) (*Broker, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.Audit == nil {
		return nil, ErrAuditRequired
	}
	if opts.Approver == nil {
		return nil, ErrApprovalUnavailable
	}
	if opts.Resolver == nil {
		return nil, ErrNoResolver
	}
	store := opts.Store
	if store == nil {
		store = policy.NewStore(now)
	}
	cache := opts.Cache
	if cache == nil {
		cache = secretcache.NewSecretCache()
	}
	fetchLimit := opts.FetchLimit
	if fetchLimit <= 0 {
		fetchLimit = 4
	}
	broker := &Broker{
		now:        now,
		approver:   opts.Approver,
		resolver:   opts.Resolver,
		audit:      opts.Audit,
		fetchLimit: fetchLimit,
		active:     make(map[string]*activeExec),
		stop:       make(chan struct{}),
	}
	broker.reusable = newReusableGrantManager(now, store, cache, broker.stopped)
	return broker, nil
}

func (b *Broker) handleExecDelivery(
	ctx context.Context,
	requestID string,
	nonce string,
	req request.ExecRequest,
) (execDelivery, error) {
	grant, err := b.handleExec(ctx, requestID, nonce, req)
	if err != nil {
		return execDelivery{}, err
	}
	return execDelivery{
		broker:    b,
		requestID: requestID,
		payload: protocol.ExecResponsePayload{
			Env:           grant.Env,
			SecretAliases: grant.SecretAliases,
		},
		expiresAt: grant.deliveryExpiresAt,
	}, nil
}

func (d execDelivery) deliver(write func(protocol.ExecResponsePayload, time.Time) error) error {
	if err := write(d.payload, d.expiresAt); err != nil {
		d.broker.markPayloadDeliveryFailed(d.requestID)
		return err
	}
	return d.broker.markPayloadDelivered(d.requestID)
}

func (b *Broker) handleExec(ctx context.Context, requestID string, nonce string, req request.ExecRequest) (ExecGrant, error) {
	if requestID == "" || nonce == "" {
		return ExecGrant{}, ErrInvalidNonce
	}
	if b.stopped() {
		return ExecGrant{}, ErrDaemonStopped
	}
	if err := b.preflightAudit(ctx); err != nil {
		return ExecGrant{}, err
	}
	if req.Expired(b.now()) {
		return ExecGrant{}, ErrRequestExpired
	}
	execCtx, cancelExec := b.requestContext(ctx, req)
	defer cancelExec()
	if err := b.requestActive(execCtx, req); err != nil {
		return ExecGrant{}, err
	}

	grant, err := b.reusableGrant(execCtx, req)
	if err != nil {
		return ExecGrant{}, b.requestError(execCtx, req, err)
	}
	if grant.Env == nil {
		grant, err = b.freshGrant(execCtx, requestID, nonce, req)
		if err != nil {
			return ExecGrant{}, b.requestError(execCtx, req, err)
		}
	}
	if err := b.ensureGrantStillActive(execCtx, req, grant.ApprovalID, grant.approvalExpiresAt); err != nil {
		b.reusable.rollbackGrant(grant)
		return ExecGrant{}, err
	}
	grant.deliveryExpiresAt = grantDeliveryExpiresAt(req, grant.approvalExpiresAt)

	event := audit.FromExecRequest(audit.EventCommandStarting, requestID, req)
	if err := b.recordRequiredAudit(execCtx, event); err != nil {
		b.reusable.rollbackGrant(grant)
		return ExecGrant{}, err
	}
	if err := b.ensureGrantStillActive(execCtx, req, grant.ApprovalID, grant.approvalExpiresAt); err != nil {
		b.reusable.rollbackGrant(grant)
		return ExecGrant{}, err
	}

	b.mu.Lock()
	b.active[requestID] = &activeExec{
		nonce:             nonce,
		req:               req,
		approvalID:        grant.ApprovalID,
		approvalExpiresAt: grant.approvalExpiresAt,
	}
	b.mu.Unlock()

	return grant, nil
}

func grantDeliveryExpiresAt(req request.ExecRequest, approvalExpiresAt time.Time) time.Time {
	if !approvalExpiresAt.IsZero() && approvalExpiresAt.Before(req.ExpiresAt) {
		return approvalExpiresAt
	}
	return req.ExpiresAt
}

func (b *Broker) requestContext(ctx context.Context, req request.ExecRequest) (context.Context, context.CancelFunc) {
	ttl := req.ExpiresAt.Sub(b.now())
	ttlCtx, cancelTTL := context.WithTimeout(ctx, ttl)
	execCtx, cancelExec := context.WithCancelCause(ttlCtx)
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-b.stop:
			cancelExec(ErrDaemonStopped)
		case <-execCtx.Done():
		case <-watcherDone:
		}
	}()

	return execCtx, func() {
		close(watcherDone)
		cancelExec(context.Canceled)
		cancelTTL()
	}
}

func (b *Broker) requestActive(ctx context.Context, req request.ExecRequest) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), ErrDaemonStopped) {
			return ErrDaemonStopped
		}
		if errors.Is(err, context.DeadlineExceeded) && req.Expired(b.now()) {
			return ErrRequestExpired
		}
		return err
	}
	if b.stopped() {
		return ErrDaemonStopped
	}
	if req.Expired(b.now()) {
		return ErrRequestExpired
	}
	return nil
}

func (b *Broker) ensureGrantStillActive(
	ctx context.Context,
	req request.ExecRequest,
	approvalID string,
	approvalExpiresAt time.Time,
) error {
	if err := b.requestActive(ctx, req); err != nil {
		return err
	}
	return b.reusable.ensureApprovalActive(approvalID, approvalExpiresAt)
}

func (b *Broker) requestError(ctx context.Context, req request.ExecRequest, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrApprovalDenied) || errors.Is(err, ErrRequestExpired) {
		return err
	}
	if activeErr := b.requestActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, ErrRequestExpired) {
			return activeErr
		}
	}
	return err
}

func (b *Broker) markPayloadDelivered(requestID string) error {
	if b.stopped() {
		return ErrDaemonStopped
	}
	active, ok := b.lookupActiveExec(requestID)
	if !ok {
		return ErrUnknownRequest
	}
	if b.stopped() {
		b.removeActiveExec(requestID)
		return ErrDaemonStopped
	}
	if active.approvalID == "" {
		b.markActivePayloadDelivered(requestID)
		return nil
	}
	if err := b.reusable.ensureApprovalActive(active.approvalID, active.approvalExpiresAt); err != nil {
		b.removeActiveExec(requestID)
		return err
	}
	if err := b.reusable.finishPayloadDelivered(active.approvalID); err != nil {
		b.removeActiveExec(requestID)
		return err
	}
	if b.stopped() {
		b.removeActiveExec(requestID)
		return ErrDaemonStopped
	}
	b.markActivePayloadDelivered(requestID)
	return nil
}

func (b *Broker) lookupActiveExec(requestID string) (*activeExec, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	active, ok := b.active[requestID]
	return active, ok
}

func (b *Broker) removeActiveExec(requestID string) {
	b.mu.Lock()
	delete(b.active, requestID)
	b.mu.Unlock()
}

func (b *Broker) markActivePayloadDelivered(requestID string) {
	b.mu.Lock()
	if current := b.active[requestID]; current != nil {
		current.payloadDelivered = true
	}
	b.mu.Unlock()
}

func (b *Broker) markPayloadDeliveryFailed(requestID string) {
	b.mu.Lock()
	active, ok := b.active[requestID]
	if ok {
		delete(b.active, requestID)
	}
	b.mu.Unlock()
	if !ok || active.payloadDelivered || active.approvalID == "" {
		return
	}

	b.reusable.finishPrePayloadFailure(active.approvalID)
}

func (b *Broker) ReportStarted(ctx context.Context, requestID string, nonce string, childPID int) error {
	active, err := b.activeRequest(requestID, nonce)
	if err != nil {
		return err
	}

	event := audit.FromExecRequest(audit.EventCommandStarted, requestID, active.req)
	pid := childPID
	event.ChildPID = &pid
	if err := b.recordRequiredAudit(ctx, event); err != nil {
		return err
	}

	b.mu.Lock()
	if current := b.active[requestID]; current != nil {
		current.started = true
		current.childPID = &pid
	}
	b.mu.Unlock()
	return nil
}

func (b *Broker) ReportCompleted(ctx context.Context, requestID string, nonce string, exitCode int, signal string) error {
	active, err := b.activeRequest(requestID, nonce)
	if err != nil {
		return err
	}

	event := audit.FromExecRequest(audit.EventCommandCompleted, requestID, active.req)
	event.ExitCode = new(exitCode)
	event.Signal = signal
	if err := b.recordRequiredAudit(ctx, event); err != nil {
		return err
	}

	b.mu.Lock()
	delete(b.active, requestID)
	b.mu.Unlock()
	return nil
}

func (b *Broker) ClientDisconnected(ctx context.Context, requestID string) {
	b.mu.Lock()
	active, ok := b.active[requestID]
	if ok {
		delete(b.active, requestID)
	}
	b.mu.Unlock()
	if !ok || !active.payloadDelivered {
		return
	}

	eventType := audit.EventExecClientDisconnectedAfterPayload
	if active.started {
		eventType = audit.EventExecClientDisconnectedAfterStart
	}
	event := audit.FromExecRequest(eventType, requestID, active.req)
	event.ChildPID = active.childPID
	_ = b.audit.Record(ctx, event)
}

func (b *Broker) Stop(ctx context.Context) {
	b.stopWithAudit(ctx, audit.Event{Type: audit.EventDaemonStop})
}

func (b *Broker) stopWithAudit(ctx context.Context, event audit.Event) {
	b.stopOnce.Do(func() { close(b.stop) })
	b.recordDaemonStopAttempt(ctx, event)
	b.mu.Lock()
	b.active = make(map[string]*activeExec)
	b.mu.Unlock()
	b.reusable.clear()
}

func (b *Broker) recordDaemonStopAttempt(ctx context.Context, event audit.Event) {
	if event.Type == "" {
		event.Type = audit.EventDaemonStop
	}
	_ = b.audit.Record(ctx, event)
}

func (b *Broker) reusableGrant(ctx context.Context, req request.ExecRequest) (ExecGrant, error) {
	return b.reusable.tryGrant(
		ctx,
		req,
		b.audit,
		func(policy.ReusableApproval) (map[secretIdentity]string, error) {
			refValues, err := b.resolveUniqueRefs(ctx, "", req)
			if err != nil {
				return nil, b.requestError(ctx, req, err)
			}
			return refValues, nil
		},
		func(approval policy.ReusableApproval) error {
			event := audit.FromExecRequest(audit.EventApprovalRefreshed, "", req)
			event.ApprovalID = approval.ID
			return b.recordRequiredAudit(ctx, event)
		},
		func(approval policy.ReusableApproval) error {
			return b.ensureGrantStillActive(ctx, req, approval.ID, approval.ExpiresAt)
		},
	)
}

func (b *Broker) preflightAudit(ctx context.Context) error {
	if err := b.audit.Preflight(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}
	return nil
}

func (b *Broker) freshGrant(
	ctx context.Context,
	requestID string,
	nonce string,
	req request.ExecRequest,
) (ExecGrant, error) {
	if err := b.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalRequested, requestID, req)); err != nil {
		return ExecGrant{}, err
	}
	decision, err := b.approver.ApproveExec(ctx, requestID, nonce, req)
	if err != nil {
		if auditErr := b.recordApprovalError(ctx, requestID, req, err); auditErr != nil {
			return ExecGrant{}, auditErr
		}
		return ExecGrant{}, err
	}
	if !decision.Approved {
		if err := b.recordApprovalDenied(ctx, requestID, req); err != nil {
			return ExecGrant{}, err
		}
		return ExecGrant{}, ErrApprovalDenied
	}
	if err := b.requestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}
	if err := b.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalGranted, requestID, req)); err != nil {
		return ExecGrant{}, err
	}
	if err := b.requestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}

	refValues, err := b.resolveUniqueRefs(ctx, requestID, req)
	if err != nil {
		return ExecGrant{}, b.requestError(ctx, req, err)
	}
	if err := b.requestActive(ctx, req); err != nil {
		return ExecGrant{}, err
	}
	values := fanoutValues(req.Secrets, refValues)

	approvalID, approvalExpiresAt, err := b.reusable.createGrant(req, decision, refValues)
	if err != nil {
		return ExecGrant{}, err
	}

	return ExecGrant{
		Env:                values,
		SecretAliases:      aliases(req.Secrets),
		ApprovalID:         approvalID,
		reusableMutationID: approvalID,
		approvalExpiresAt:  approvalExpiresAt,
	}, nil
}

func reusableMutationID(mutated bool, approvalID string) string {
	if !mutated {
		return ""
	}
	return approvalID
}

func (b *Broker) resolveUniqueRefs(ctx context.Context, requestID string, req request.ExecRequest) (map[secretIdentity]string, error) {
	secrets := req.Secrets
	identities := uniqueSecretIdentities(secrets)
	type result struct {
		identity secretIdentity
		value    string
		err      error
	}

	if err := b.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventSecretFetchStarted, requestID, req)); err != nil {
		return nil, err
	}

	fetchCtx, cancelFetches := context.WithCancel(ctx)
	defer cancelFetches()

	sem := make(chan struct{}, b.fetchLimit)
	results := make(chan result, len(identities))
	for _, identity := range identities {
		go func(identity secretIdentity) {
			select {
			case sem <- struct{}{}:
			case <-fetchCtx.Done():
				return
			}
			defer func() { <-sem }()

			value, err := b.resolver.Resolve(fetchCtx, identity.ref, identity.account)
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
			if auditErr := b.recordSecretFetchFailedForIdentities(
				ctx,
				requestID,
				secrets,
				pendingIdentities(identities, pending),
				err,
			); auditErr != nil {
				return nil, auditErr
			}
			return nil, fmt.Errorf("resolve approved ref: %w", err)
		}

		if got.err != nil {
			cancelFetches()
			if err := b.recordSecretFetchFailed(ctx, requestID, secrets, got.identity, got.err); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("resolve approved ref: %w", got.err)
		}
		resolved[got.identity] = got.value
	}

	return resolved, nil
}

func (b *Broker) recordRequiredAudit(ctx context.Context, event audit.Event) error {
	if err := b.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}
	return nil
}

func terminalAuditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func (b *Broker) recordApprovalError(
	ctx context.Context,
	requestID string,
	req request.ExecRequest,
	err error,
) error {
	switch {
	case errors.Is(err, ErrApprovalDenied):
		return b.recordApprovalDenied(ctx, requestID, req)
	case errors.Is(err, ErrRequestExpired):
		event := audit.FromExecRequest(audit.EventApprovalTimedOut, requestID, req)
		event.ErrorCode = string(protocol.ErrorCodeRequestExpired)
		auditCtx, cancel := terminalAuditContext(ctx)
		defer cancel()
		return b.recordRequiredAudit(auditCtx, event)
	default:
		return nil
	}
}

func (b *Broker) recordApprovalDenied(ctx context.Context, requestID string, req request.ExecRequest) error {
	event := audit.FromExecRequest(audit.EventApprovalDenied, requestID, req)
	event.ErrorCode = string(protocol.ErrorCodeApprovalDenied)
	auditCtx, cancel := terminalAuditContext(ctx)
	defer cancel()
	return b.recordRequiredAudit(auditCtx, event)
}

func (b *Broker) recordSecretFetchFailed(
	ctx context.Context,
	requestID string,
	secrets []request.Secret,
	identity secretIdentity,
	err error,
) error {
	return b.recordSecretFetchFailureEvent(ctx, requestID, auditRefsForIdentity(secrets, identity), err)
}

func (b *Broker) recordSecretFetchFailedForIdentities(
	ctx context.Context,
	requestID string,
	secrets []request.Secret,
	identities []secretIdentity,
	err error,
) error {
	return b.recordSecretFetchFailureEvent(ctx, requestID, auditRefsForIdentities(secrets, identities), err)
}

func (b *Broker) recordSecretFetchFailureEvent(
	ctx context.Context,
	requestID string,
	refs []audit.SecretRef,
	err error,
) error {
	event := audit.Event{
		Type:       audit.EventSecretFetchFailed,
		RequestID:  requestID,
		SecretRefs: refs,
		ErrorCode:  string(secretFetchErrorCode(err)),
	}
	auditCtx, cancel := terminalAuditContext(ctx)
	defer cancel()
	return b.recordRequiredAudit(auditCtx, event)
}

func secretFetchErrorCode(err error) protocol.ErrorCode {
	if errors.Is(err, ErrDaemonStopped) {
		return protocol.ErrorCodeDaemonStopped
	}
	if errors.Is(err, context.Canceled) {
		return protocol.ErrorCodeContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return protocol.ErrorCodeContextDeadlineExceeded
	}
	return protocol.ErrorCodeResolveFailed
}

func contextCause(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func auditRefsForIdentity(secrets []request.Secret, identity secretIdentity) []audit.SecretRef {
	refs := []audit.SecretRef{}
	for _, secret := range secrets {
		if secret.Ref.Raw != identity.ref || secret.Account != identity.account {
			continue
		}
		refs = append(refs, audit.SecretRef{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	if len(refs) == 0 {
		return []audit.SecretRef{{Ref: identity.ref, Account: identity.account}}
	}
	return refs
}

func auditRefsForIdentities(secrets []request.Secret, identities []secretIdentity) []audit.SecretRef {
	refs := []audit.SecretRef{}
	seen := make(map[secretIdentity]struct{}, len(identities))
	for _, identity := range identities {
		seen[identity] = struct{}{}
	}
	matched := make(map[secretIdentity]struct{}, len(identities))
	for _, secret := range secrets {
		identity := secretIdentity{ref: secret.Ref.Raw, account: secret.Account}
		if _, ok := seen[identity]; !ok {
			continue
		}
		matched[identity] = struct{}{}
		refs = append(refs, audit.SecretRef{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	for _, identity := range identities {
		if _, ok := matched[identity]; ok {
			continue
		}
		refs = append(refs, audit.SecretRef{Ref: identity.ref, Account: identity.account})
	}
	return refs
}

func pendingIdentities(ordered []secretIdentity, pending map[secretIdentity]struct{}) []secretIdentity {
	identities := make([]secretIdentity, 0, len(pending))
	for _, identity := range ordered {
		if _, ok := pending[identity]; ok {
			identities = append(identities, identity)
		}
	}
	return identities
}

func (b *Broker) activeRequest(requestID string, nonce string) (*activeExec, error) {
	if b.stopped() {
		return nil, ErrDaemonStopped
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	active, ok := b.active[requestID]
	if !ok {
		return nil, ErrUnknownRequest
	}
	if active.nonce != nonce {
		return nil, ErrInvalidNonce
	}
	return active, nil
}

func (b *Broker) stopped() bool {
	select {
	case <-b.stop:
		return true
	default:
		return false
	}
}

type secretIdentity struct {
	ref     string
	account string
}

func uniqueSecretIdentities(secrets []request.Secret) []secretIdentity {
	seen := make(map[secretIdentity]struct{}, len(secrets))
	identities := make([]secretIdentity, 0, len(secrets))
	for _, secret := range secrets {
		identity := secretIdentity{ref: secret.Ref.Raw, account: secret.Account}
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, func(a secretIdentity, b secretIdentity) int {
		if a.ref < b.ref {
			return -1
		}
		if a.ref > b.ref {
			return 1
		}
		if a.account < b.account {
			return -1
		}
		if a.account > b.account {
			return 1
		}
		return 0
	})
	return identities
}

func fanoutValues(secrets []request.Secret, refValues map[secretIdentity]string) map[string]string {
	values := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		values[secret.Alias] = refValues[secretIdentity{ref: secret.Ref.Raw, account: secret.Account}]
	}
	return values
}

func aliases(secrets []request.Secret) []string {
	aliases := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		aliases = append(aliases, secret.Alias)
	}
	slices.Sort(aliases)
	return aliases
}
