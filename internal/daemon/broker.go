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
	Resolve(ctx context.Context, ref string) (string, error)
}

type AuditSink interface {
	policy.ReuseAuditSink
	Record(ctx context.Context, event audit.Event) error
}

type Broker struct {
	mu         sync.Mutex
	now        func() time.Time
	store      *policy.Store
	cache      *policy.SecretCache
	approver   Approver
	resolver   Resolver
	audit      AuditSink
	fetchLimit int
	active     map[string]*activeExec
}

type ExecGrant struct {
	Env           map[string]string
	SecretAliases []string
	ApprovalID    string
}

type activeExec struct {
	nonce            string
	req              request.ExecRequest
	approvalID       string
	payloadDelivered bool
	started          bool
}

type BrokerOptions struct {
	Now        func() time.Time
	Store      *policy.Store
	Cache      *policy.SecretCache
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
	if err := b.audit.Record(ctx, event); err != nil {
		return ExecGrant{}, fmt.Errorf("%w: %w", ErrAuditRequired, err)
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
	_, err := b.store.FinishReusableAttempt(active.approvalID, policy.DeliveryPayloadDelivered)
	return err
}

func (b *Broker) ReportStarted(ctx context.Context, requestID string, nonce string, childPID int) error {
	active, err := b.activeRequest(requestID, nonce)
	if err != nil {
		return err
	}

	event := audit.FromExecRequest(audit.EventCommandStarted, requestID, active.req)
	event.ChildPID = new(childPID)
	if err := b.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
	}

	b.mu.Lock()
	if current := b.active[requestID]; current != nil {
		current.started = true
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
	if err := b.audit.Record(ctx, event); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditRequired, err)
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
	if !ok || !active.payloadDelivered || active.started {
		return
	}

	event := audit.FromExecRequest(audit.EventExecClientDisconnectedAfterPayload, requestID, active.req)
	_ = b.audit.Record(ctx, event)
}

func (b *Broker) Stop(ctx context.Context) {
	_ = b.audit.Record(ctx, audit.Event{Type: audit.EventDaemonStop})
	b.mu.Lock()
	defer b.mu.Unlock()
	b.active = make(map[string]*activeExec)
	b.cache = policy.NewSecretCache()
	b.store = policy.NewStore(b.now)
}

func (b *Broker) reusableGrant(ctx context.Context, req request.ExecRequest) (ExecGrant, error) {
	approval, err := b.store.FindReusable(ctx, req, b.audit)
	if err != nil {
		if errors.Is(err, policy.ErrAuditFailed) {
			return ExecGrant{}, err
		}
		return ExecGrant{}, nil
	}

	var values map[string]string
	if req.ForceRefresh {
		refValues, err := b.resolveUniqueRefs(ctx, req.Secrets)
		if err != nil {
			return ExecGrant{}, err
		}
		values = fanoutValues(req.Secrets, refValues)
		for ref, value := range refValues {
			b.cache.Put(approval.ID, ref, value)
		}
		event := audit.FromExecRequest(audit.EventApprovalRefreshed, "", req)
		event.ApprovalID = approval.ID
		if err := b.audit.Record(ctx, event); err != nil {
			return ExecGrant{}, fmt.Errorf("%w: %w", ErrAuditRequired, err)
		}
	} else {
		var err error
		values, err = b.cachedValues(approval.ID, req.Secrets)
		if err != nil {
			return ExecGrant{}, err
		}
	}

	return ExecGrant{
		Env:           values,
		SecretAliases: aliases(req.Secrets),
		ApprovalID:    approval.ID,
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
	decision, err := b.approver.ApproveExec(ctx, requestID, nonce, req)
	if err != nil {
		return ExecGrant{}, err
	}
	if !decision.Approved {
		return ExecGrant{}, ErrApprovalDenied
	}

	refValues, err := b.resolveUniqueRefs(ctx, req.Secrets)
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
		for ref, value := range refValues {
			b.cache.Put(approvalID, ref, value)
		}
	}

	return ExecGrant{
		Env:           values,
		SecretAliases: aliases(req.Secrets),
		ApprovalID:    approvalID,
	}, nil
}

func (b *Broker) resolveUniqueRefs(ctx context.Context, secrets []request.Secret) (map[string]string, error) {
	refs := uniqueRefs(secrets)
	type result struct {
		ref   string
		value string
		err   error
	}

	sem := make(chan struct{}, b.fetchLimit)
	results := make(chan result, len(refs))
	for _, ref := range refs {
		sem <- struct{}{}
		go func(ref string) {
			defer func() { <-sem }()
			value, err := b.resolver.Resolve(ctx, ref)
			results <- result{ref: ref, value: value, err: err}
		}(ref)
	}

	resolved := make(map[string]string, len(refs))
	for range refs {
		got := <-results
		if got.err != nil {
			return nil, fmt.Errorf("resolve approved ref: %w", got.err)
		}
		resolved[got.ref] = got.value
	}

	return resolved, nil
}

func (b *Broker) cachedValues(approvalID string, secrets []request.Secret) (map[string]string, error) {
	env := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		value, ok := b.cache.Get(approvalID, secret.Ref.Raw)
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

func uniqueRefs(secrets []request.Secret) []string {
	seen := make(map[string]struct{}, len(secrets))
	refs := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if _, ok := seen[secret.Ref.Raw]; ok {
			continue
		}
		seen[secret.Ref.Raw] = struct{}{}
		refs = append(refs, secret.Ref.Raw)
	}
	slices.Sort(refs)
	return refs
}

func fanoutValues(secrets []request.Secret, refValues map[string]string) map[string]string {
	values := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		values[secret.Alias] = refValues[secret.Ref.Raw]
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
