package daemon

import (
	"context"
	"errors"
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
	ErrSecretResolveFailed  = errors.New("secret resolve failed")
	ErrRequestAlreadyActive = errors.New("connection already has an active exec request")
	ErrDaemonStopped        = errors.New("daemon stopped")
	ErrRequestExpired       = errors.New("request expired")
	ErrUnknownRequest       = errors.New("unknown request")
)

type Approver interface {
	ApproveExec(ctx context.Context, correlation protocol.Correlation, req request.ExecRequest) (ApprovalDecision, error)
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
	mu       sync.Mutex
	now      func() time.Time
	grants   *grantIssuer
	audit    AuditSink
	active   map[string]*activeExec
	stopOnce sync.Once
	stop     chan struct{}
}

type execDelivery struct {
	broker    *Broker
	requestID string
	grant     ExecGrant
	payload   protocol.ExecResponsePayload
	expiresAt time.Time
}

type activeExec struct {
	nonce            string
	req              request.ExecRequest
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
		cache = secretcache.NewSecretCache()
	}
	fetchLimit := opts.FetchLimit
	if fetchLimit <= 0 {
		fetchLimit = 4
	}
	broker := &Broker{
		now:    now,
		audit:  opts.Audit,
		active: make(map[string]*activeExec),
		stop:   make(chan struct{}),
	}
	broker.grants = newGrantIssuer(
		now,
		store,
		cache,
		opts.Approver,
		opts.Resolver,
		broker.audit,
		fetchLimit,
		broker.stopped,
	)
	return broker, nil
}

func (b *Broker) handleExecDelivery(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (execDelivery, error) {
	grant, err := b.handleExec(ctx, correlation, req)
	if err != nil {
		return execDelivery{}, err
	}
	return execDelivery{
		broker:    b,
		requestID: correlation.RequestID,
		grant:     grant,
		payload: protocol.ExecResponsePayload{
			Env:           grant.Env,
			SecretAliases: grant.SecretAliases,
		},
		expiresAt: grant.deliveryExpiresAt,
	}, nil
}

func (d execDelivery) deliver(write func(protocol.ExecResponsePayload, time.Time) error) error {
	writeErr := write(d.payload, d.expiresAt)
	if err := d.broker.grants.completePayloadWrite(d.grant, writeErr == nil); err != nil {
		d.broker.removeActiveExec(d.requestID)
		return err
	}
	if writeErr != nil {
		d.broker.removeActiveExec(d.requestID)
		return writeErr
	}
	return d.broker.markPayloadDelivered(d.requestID)
}

func (b *Broker) handleExec(ctx context.Context, correlation protocol.Correlation, req request.ExecRequest) (ExecGrant, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return ExecGrant{}, ErrInvalidNonce
	}
	if b.stopped() {
		return ExecGrant{}, ErrDaemonStopped
	}
	if err := b.grants.preflightAudit(ctx); err != nil {
		return ExecGrant{}, err
	}
	if req.Expired(b.now()) {
		return ExecGrant{}, ErrRequestExpired
	}
	execCtx, cancelExec := b.requestContext(ctx, req)
	defer cancelExec()
	grant, err := b.grants.issue(execCtx, correlation, req)
	if err != nil {
		return ExecGrant{}, err
	}

	b.mu.Lock()
	b.active[correlation.RequestID] = &activeExec{
		nonce: correlation.Nonce,
		req:   req,
	}
	b.mu.Unlock()

	return grant, nil
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

func (b *Broker) markPayloadDelivered(requestID string) error {
	if b.stopped() {
		return ErrDaemonStopped
	}
	if !b.markActivePayloadDelivered(requestID) {
		return ErrUnknownRequest
	}
	return nil
}

func (b *Broker) removeActiveExec(requestID string) {
	b.mu.Lock()
	delete(b.active, requestID)
	b.mu.Unlock()
}

func (b *Broker) markActivePayloadDelivered(requestID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if current := b.active[requestID]; current != nil {
		current.payloadDelivered = true
		return true
	}
	return false
}

func (b *Broker) ReportStarted(ctx context.Context, correlation protocol.Correlation, childPID int) error {
	active, err := b.activeRequest(correlation)
	if err != nil {
		return err
	}

	event := audit.FromExecRequest(audit.EventCommandStarted, correlation.RequestID, active.req)
	pid := childPID
	event.ChildPID = &pid
	if err := b.grants.recordRequiredAudit(ctx, event); err != nil {
		return err
	}

	b.mu.Lock()
	if current := b.active[correlation.RequestID]; current != nil {
		current.started = true
		current.childPID = &pid
	}
	b.mu.Unlock()
	return nil
}

func (b *Broker) ReportCompleted(ctx context.Context, correlation protocol.Correlation, exitCode int, signal string) error {
	active, err := b.activeRequest(correlation)
	if err != nil {
		return err
	}

	event := audit.FromExecRequest(audit.EventCommandCompleted, correlation.RequestID, active.req)
	event.ExitCode = new(exitCode)
	event.Signal = signal
	if err := b.grants.recordRequiredAudit(ctx, event); err != nil {
		return err
	}

	b.mu.Lock()
	delete(b.active, correlation.RequestID)
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
	b.grants.clearReusableGrants()
}

func (b *Broker) recordDaemonStopAttempt(ctx context.Context, event audit.Event) {
	if event.Type == "" {
		event.Type = audit.EventDaemonStop
	}
	_ = b.audit.Record(ctx, event)
}

func terminalAuditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
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

func auditErrorCode(code protocol.ErrorCode) audit.ErrorCode {
	return audit.ErrorCode(code)
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

func (b *Broker) activeRequest(correlation protocol.Correlation) (*activeExec, error) {
	if b.stopped() {
		return nil, ErrDaemonStopped
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	active, ok := b.active[correlation.RequestID]
	if !ok {
		return nil, ErrUnknownRequest
	}
	if active.nonce != correlation.Nonce {
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
