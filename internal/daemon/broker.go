package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrApprovalDenied      = errors.New("approval denied")
	ErrApprovalUnavailable = errors.New("approval unavailable")
	ErrAuditRequired       = errors.New("audit required")
	ErrInvalidNonce        = errors.New("invalid request nonce")
	ErrMissingCache        = errors.New("approved secret cache entry missing")
	ErrNoResolver          = errors.New("secret resolver unavailable")
	ErrRequestExpired      = errors.New("request expired")
	ErrUnknownRequest      = errors.New("unknown request")
)

type Approver interface {
	ApproveExec(ctx context.Context, requestID string, nonce string, req request.ExecRequest) (ApprovalDecision, error)
}

type ApprovalDecision struct {
	Approved bool
	Reusable bool
}

type Resolver interface {
	Resolve(ctx context.Context, ref string, account string) (string, error)
}

type AuditSink interface {
	policy.ReuseAuditSink
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
	store      *policy.Store
	cache      SecretCache
	approver   Approver
	resolver   Resolver
	audit      AuditSink
	fetchLimit int
	active     map[string]*activeExec
	expiry     map[string]*time.Timer
}

type ExecGrant struct {
	Env                map[string]string
	SecretAliases      []string
	ApprovalID         string
	reusableMutationID string
}

type activeExec struct {
	nonce            string
	req              request.ExecRequest
	approvalID       string
	payloadDelivered bool
	started          bool
	childPID         *int
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
		cache = policy.NewSecretCache()
	}
	fetchLimit := opts.FetchLimit
	if fetchLimit <= 0 {
		fetchLimit = 4
	}

	return &Broker{
		now:        now,
		store:      store,
		cache:      cache,
		approver:   opts.Approver,
		resolver:   opts.Resolver,
		audit:      opts.Audit,
		fetchLimit: fetchLimit,
		active:     make(map[string]*activeExec),
		expiry:     make(map[string]*time.Timer),
	}, nil
}

func (b *Broker) HandleExec(ctx context.Context, requestID string, nonce string, req request.ExecRequest) (ExecGrant, error) {
	if requestID == "" || nonce == "" {
		return ExecGrant{}, ErrInvalidNonce
	}
	if err := b.preflightAudit(ctx); err != nil {
		return ExecGrant{}, err
	}
	if req.Expired(b.now()) {
		return ExecGrant{}, ErrRequestExpired
	}

	grant, err := b.reusableGrant(ctx, req)
	if err != nil {
		return ExecGrant{}, err
	}
	if grant.Env == nil {
		grant, err = b.freshGrant(ctx, requestID, nonce, req)
		if err != nil {
			return ExecGrant{}, err
		}
	}

	event := audit.FromExecRequest(audit.EventCommandStarting, requestID, req)
	if err := b.recordRequiredAudit(ctx, event); err != nil {
		b.rollbackReusableApproval(grant.reusableMutationID)
		return ExecGrant{}, err
	}

	b.mu.Lock()
	b.active[requestID] = &activeExec{
		nonce:      nonce,
		req:        req,
		approvalID: grant.ApprovalID,
	}
	b.mu.Unlock()

	return grant, nil
}

func (b *Broker) MarkPayloadDelivered(requestID string) error {
	b.mu.Lock()
	active, ok := b.active[requestID]
	if ok {
		active.payloadDelivered = true
	}
	b.mu.Unlock()
	if !ok {
		return ErrUnknownRequest
	}
	if active.approvalID == "" {
		return nil
	}
	approval, err := b.store.FinishReusableAttempt(active.approvalID, policy.DeliveryPayloadDelivered)
	if err == nil && approval.Uses >= approval.MaxUses {
		b.clearReusableCacheScope(approval.ID)
	}
	return err
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
	b.recordDaemonStopAttempt(ctx, event)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active = make(map[string]*activeExec)
	for id, timer := range b.expiry {
		timer.Stop()
		delete(b.expiry, id)
	}
	b.cache.Clear()
	b.store = policy.NewStore(b.now)
}

func (b *Broker) recordDaemonStopAttempt(ctx context.Context, event audit.Event) {
	if event.Type == "" {
		event.Type = audit.EventDaemonStop
	}
	_ = b.audit.Record(ctx, event)
}

func (b *Broker) reusableGrant(ctx context.Context, req request.ExecRequest) (ExecGrant, error) {
	approval, err := b.store.FindReusable(ctx, req, b.audit)
	if err != nil {
		if errors.Is(err, policy.ErrAuditFailed) {
			return ExecGrant{}, err
		}
		if approval.ID != "" && (errors.Is(err, policy.ErrExpired) || errors.Is(err, policy.ErrUseExhausted)) {
			b.clearReusableCacheScope(approval.ID)
		}
		return ExecGrant{}, nil
	}

	var values map[string]string
	var valueErr error
	if req.ForceRefresh {
		values, valueErr = b.refreshedReusableValues(ctx, approval.ID, req)
	} else {
		values, valueErr = b.cachedValues(approval.ID, req.Secrets)
	}
	if valueErr != nil {
		return ExecGrant{}, valueErr
	}

	return ExecGrant{
		Env:                values,
		SecretAliases:      aliases(req.Secrets),
		ApprovalID:         approval.ID,
		reusableMutationID: reusableMutationID(req.ForceRefresh, approval.ID),
	}, nil
}

func (b *Broker) preflightAudit(ctx context.Context) error {
	preflighter, ok := b.audit.(interface {
		Preflight(ctx context.Context) error
	})
	if !ok {
		return nil
	}
	if err := preflighter.Preflight(ctx); err != nil {
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
	if err := b.recordRequiredAudit(ctx, audit.FromExecRequest(audit.EventApprovalGranted, requestID, req)); err != nil {
		return ExecGrant{}, err
	}

	refValues, err := b.resolveUniqueRefs(ctx, requestID, req)
	if err != nil {
		return ExecGrant{}, err
	}
	values := fanoutValues(req.Secrets, refValues)

	approvalID := ""
	if decision.Reusable {
		approval, err := b.store.AddReusable(req, "", "")
		if err != nil {
			return ExecGrant{}, err
		}
		approvalID = approval.ID
		if err := b.cacheResolvedValues(approvalID, refValues); err != nil {
			b.rollbackReusableApproval(approvalID)
			return ExecGrant{}, err
		}
		b.scheduleReusableExpiry(approval.ID, approval.ExpiresAt)
	}

	return ExecGrant{
		Env:                values,
		SecretAliases:      aliases(req.Secrets),
		ApprovalID:         approvalID,
		reusableMutationID: approvalID,
	}, nil
}

func reusableMutationID(mutated bool, approvalID string) string {
	if !mutated {
		return ""
	}
	return approvalID
}

func (b *Broker) rollbackReusableApproval(approvalID string) {
	if approvalID == "" {
		return
	}
	b.store.RemoveReusable(approvalID)
	b.clearReusableCacheScope(approvalID)
}

func (b *Broker) scheduleReusableExpiry(approvalID string, expiresAt time.Time) {
	ttl := expiresAt.Sub(b.now())
	if ttl <= 0 {
		b.store.RemoveReusable(approvalID)
		b.clearReusableCacheScope(approvalID)
		return
	}

	b.mu.Lock()
	if previous := b.expiry[approvalID]; previous != nil {
		previous.Stop()
	}
	timer := time.AfterFunc(ttl, func() {
		b.store.RemoveReusable(approvalID)
		b.clearReusableCacheScope(approvalID)
	})
	b.expiry[approvalID] = timer
	b.mu.Unlock()
}

func (b *Broker) clearReusableCacheScope(approvalID string) {
	b.mu.Lock()
	if timer := b.expiry[approvalID]; timer != nil {
		timer.Stop()
		delete(b.expiry, approvalID)
	}
	b.mu.Unlock()
	b.cache.ClearScope(approvalID)
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
	var wg sync.WaitGroup
	for _, identity := range identities {
		wg.Add(1)
		go func(identity secretIdentity) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-fetchCtx.Done():
				return
			}
			defer func() { <-sem }()

			value, err := b.resolver.Resolve(fetchCtx, identity.ref, identity.account)
			results <- result{identity: identity, value: value, err: err}
		}(identity)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	resolved := make(map[secretIdentity]string, len(identities))
	var firstErr error
	for got := range results {
		if got.err != nil {
			if firstErr == nil {
				cancelFetches()
				if err := b.recordSecretFetchFailed(ctx, requestID, secrets, got.identity, got.err); err != nil {
					firstErr = err
				} else {
					firstErr = fmt.Errorf("resolve approved ref: %w", got.err)
				}
			}
			continue
		}
		if firstErr == nil {
			resolved[got.identity] = got.value
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	if err := fetchCtx.Err(); err != nil {
		return nil, fmt.Errorf("resolve approved ref: %w", err)
	}

	return resolved, nil
}

func (b *Broker) refreshedReusableValues(
	ctx context.Context,
	approvalID string,
	req request.ExecRequest,
) (map[string]string, error) {
	refValues, err := b.resolveUniqueRefs(ctx, "", req)
	if err != nil {
		return nil, err
	}
	values := fanoutValues(req.Secrets, refValues)
	if err := b.cacheResolvedValues(approvalID, refValues); err != nil {
		b.rollbackReusableApproval(approvalID)
		return nil, err
	}
	event := audit.FromExecRequest(audit.EventApprovalRefreshed, "", req)
	event.ApprovalID = approvalID
	if err := b.recordRequiredAudit(ctx, event); err != nil {
		b.rollbackReusableApproval(approvalID)
		return nil, err
	}
	return values, nil
}

func (b *Broker) recordRequiredAudit(ctx context.Context, event audit.Event) error {
	if err := b.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}
	return nil
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
		event.ErrorCode = "request_expired"
		return b.recordRequiredAudit(ctx, event)
	default:
		return nil
	}
}

func (b *Broker) recordApprovalDenied(ctx context.Context, requestID string, req request.ExecRequest) error {
	event := audit.FromExecRequest(audit.EventApprovalDenied, requestID, req)
	event.ErrorCode = "approval_denied"
	return b.recordRequiredAudit(ctx, event)
}

func (b *Broker) recordSecretFetchFailed(
	ctx context.Context,
	requestID string,
	secrets []request.Secret,
	identity secretIdentity,
	err error,
) error {
	event := audit.Event{
		Type:       audit.EventSecretFetchFailed,
		RequestID:  requestID,
		SecretRefs: auditRefsForIdentity(secrets, identity),
		ErrorCode:  secretFetchErrorCode(err),
	}
	return b.recordRequiredAudit(ctx, event)
}

func secretFetchErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline_exceeded"
	}
	return "resolve_failed"
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

func (b *Broker) cacheResolvedValues(approvalID string, refValues map[secretIdentity]string) error {
	for identity, value := range refValues {
		if err := b.cache.Put(approvalID, identity.ref, identity.account, value); err != nil {
			return fmt.Errorf("cache approved secret in locked memory: %w", err)
		}
	}
	return nil
}

func (b *Broker) cachedValues(approvalID string, secrets []request.Secret) (map[string]string, error) {
	env := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		value, ok := b.cache.Get(approvalID, secret.Ref.Raw, secret.Account)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingCache, secret.Ref.Raw)
		}
		env[secret.Alias] = value
	}
	return env, nil
}

func (b *Broker) activeRequest(requestID string, nonce string) (*activeExec, error) {
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
