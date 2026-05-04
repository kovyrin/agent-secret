package broker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

var (
	ErrAuditRequired       = errors.New("audit required")
	ErrMissingCache        = errors.New("approved secret cache entry missing")
	ErrNoResolver          = errors.New("secret resolver unavailable")
	ErrSecretResolveFailed = errors.New("secret resolve failed")
	ErrDaemonStopped       = errors.New("daemon stopped")
	ErrUnknownRequest      = errors.New("unknown request")
)

type Resolver interface {
	Resolve(ctx context.Context, ref string, account string) (string, error)
}

type AuditSink interface {
	Preflight(ctx context.Context) error
	Record(ctx context.Context, event audit.Event) error
}

type SecretCache interface {
	Put(key secretcache.CacheKey, value string) error
	Get(key secretcache.CacheKey) (string, bool)
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

type activeExec struct {
	nonce    string
	req      request.ExecRequest
	started  bool
	childPID *int
}

type Options struct {
	Now        func() time.Time
	Store      *policy.Store
	Cache      SecretCache
	Approver   approval.Approver
	Resolver   Resolver
	Audit      AuditSink
	FetchLimit int
}

func New(opts Options) (*Broker, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.Audit == nil {
		return nil, ErrAuditRequired
	}
	if opts.Approver == nil {
		return nil, approval.ErrUnavailable
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

func (b *Broker) Now() time.Time {
	return b.now()
}

func (b *Broker) HandleExecDelivery(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
	write func(protocol.ExecResponsePayload, time.Time, func() error) error,
) (Grant, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return Grant{}, protocol.ErrInvalidNonce
	}
	if b.stopped() {
		return Grant{}, ErrDaemonStopped
	}
	if err := b.grants.preflightAudit(ctx); err != nil {
		return Grant{}, err
	}
	if req.Expired(b.now()) {
		return Grant{}, approval.ErrRequestExpired
	}
	execCtx, cancelExec := b.requestContext(ctx, req)
	defer cancelExec()
	issued, err := b.grants.issue(execCtx, correlation, req)
	if err != nil {
		return Grant{}, err
	}
	if err := b.activateExec(correlation, req); err != nil {
		b.grants.finishDeliveryBeforePayload(issued.delivery)
		return Grant{}, err
	}
	payload := protocol.ExecResponsePayload{
		Env:           issued.grant.Env,
		SecretAliases: issued.grant.SecretAliases,
	}
	beforeWrite := func() error {
		return b.grants.ensurePayloadWritable(execCtx, req, issued.delivery)
	}
	if err := write(payload, issued.grant.payloadExpiresAt, beforeWrite); err != nil {
		b.deactivateExec(correlation)
		b.grants.finishDeliveryBeforePayload(issued.delivery)
		return Grant{}, err
	}
	b.grants.finishDeliveryAfterPayload(issued.delivery)
	return issued.grant, nil
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

func (b *Broker) activateExec(correlation protocol.Correlation, req request.ExecRequest) error {
	if b.stopped() {
		return ErrDaemonStopped
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped() {
		return ErrDaemonStopped
	}
	b.active[correlation.RequestID] = &activeExec{
		nonce: correlation.Nonce,
		req:   req,
	}
	return nil
}

func (b *Broker) deactivateExec(correlation protocol.Correlation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	active := b.active[correlation.RequestID]
	if active != nil && active.nonce == correlation.Nonce {
		delete(b.active, correlation.RequestID)
	}
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
	if !ok {
		return
	}

	eventType := audit.EventExecClientDisconnectedAfterPayload
	if active.started {
		eventType = audit.EventExecClientDisconnectedAfterStart
	}
	event := audit.FromExecRequest(eventType, requestID, active.req)
	event.ChildPID = active.childPID
	b.recordBestEffortAudit(ctx, event)
}

func (b *Broker) StopWithAuditEvent(ctx context.Context, event audit.Event) {
	b.stopOnce.Do(func() { close(b.stop) })
	b.RecordStopAttempt(ctx, event)
	b.mu.Lock()
	b.active = make(map[string]*activeExec)
	b.mu.Unlock()
	b.grants.clearReusableGrants()
}

func (b *Broker) RecordStopAttempt(ctx context.Context, event audit.Event) {
	if event.Type == "" {
		event.Type = audit.EventDaemonStop
	}
	b.recordBestEffortAudit(ctx, event)
}

// recordBestEffortAudit documents terminal lifecycle audit writes that cannot be surfaced to a protocol caller.
func (b *Broker) recordBestEffortAudit(ctx context.Context, event audit.Event) {
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
		return nil, protocol.ErrInvalidNonce
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
