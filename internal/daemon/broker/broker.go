package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

var (
	ErrAuditRequired             = errors.New("audit required")
	ErrMissingCache              = errors.New("approved secret cache entry missing")
	ErrNoResolver                = errors.New("secret resolver unavailable")
	ErrSecretResolveFailed       = errors.New("secret resolve failed")
	ErrItemMetadataResolveFailed = errors.New("item metadata resolve failed")
	ErrDaemonStopped             = errors.New("daemon stopped")
	ErrUnknownRequest            = errors.New("unknown request")
)

type Resolver interface {
	Resolve(ctx context.Context, ref string, account string) (string, error)
	DescribeItem(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error)
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
	approver approval.Approver
	resolver Resolver
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

type itemDescribeResult struct {
	metadata itemmetadata.Metadata
	err      error
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
		now:      now,
		approver: opts.Approver,
		resolver: opts.Resolver,
		audit:    opts.Audit,
		active:   make(map[string]*activeExec),
		stop:     make(chan struct{}),
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

func (b *Broker) ActiveCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.active)
}

func (b *Broker) PrepareExecDelivery(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (*ExecDelivery, error) {
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
	issued, err := b.grants.issue(execCtx, correlation, req)
	if err != nil {
		cancelExec()
		return nil, err
	}
	if err := b.activateExec(correlation, req); err != nil {
		b.grants.finishDeliveryBeforePayload(issued.delivery)
		cancelExec()
		return nil, err
	}
	return &ExecDelivery{
		broker:        b,
		cancelExec:    cancelExec,
		correlation:   correlation,
		issued:        issued,
		beforePayload: func() error { return b.grants.ensurePayloadWritable(execCtx, req, issued.delivery) },
		payload: protocol.ExecResponsePayload{
			Env:           issued.grant.Env,
			SecretAliases: issued.grant.SecretAliases,
		},
	}, nil
}

type ExecDelivery struct {
	broker        *Broker
	cancelExec    context.CancelFunc
	correlation   protocol.Correlation
	issued        issuedGrant
	beforePayload func() error
	payload       protocol.ExecResponsePayload
	finalizeOnce  sync.Once
}

func (d *ExecDelivery) Payload() protocol.ExecResponsePayload {
	return d.payload
}

func (d *ExecDelivery) ExpiresAt() time.Time {
	return d.issued.grant.payloadExpiresAt
}

func (d *ExecDelivery) BeforeWrite() error {
	return d.beforePayload()
}

func (d *ExecDelivery) CommitDelivered() Grant {
	d.finalizeOnce.Do(func() {
		d.broker.grants.finishDeliveryAfterPayload(d.issued.delivery)
		d.cancelExec()
	})
	return d.issued.grant
}

func (d *ExecDelivery) AbortBeforePayload() {
	d.finalizeOnce.Do(func() {
		d.broker.deactivateExec(d.correlation)
		d.broker.grants.finishDeliveryBeforePayload(d.issued.delivery)
		d.cancelExec()
	})
}

func (d *ExecDelivery) Grant() Grant {
	return d.issued.grant
}

func (b *Broker) HandleItemDescribe(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.ItemDescribeRequest,
) (protocol.ItemDescribeResponsePayload, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return protocol.ItemDescribeResponsePayload{}, protocol.ErrInvalidNonce
	}
	if b.stopped() {
		return protocol.ItemDescribeResponsePayload{}, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if req.Expired(b.now()) {
		return protocol.ItemDescribeResponsePayload{}, approval.ErrRequestExpired
	}
	itemCtx, cancelItem := b.requestContext(ctx, req.ExpiresAt)
	defer cancelItem()

	if err := recordRequiredAudit(itemCtx, b.audit, audit.FromItemDescribeRequest(audit.EventItemMetadataRequested, correlation.RequestID, req)); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	decision, err := b.approver.Approve(itemCtx, approval.NewItemDescribePayload(correlation, req))
	if err != nil {
		if auditErr := recordTerminalRequiredAudit(ctx, b.audit, itemDescribeErrorEvent(correlation.RequestID, req, err)); auditErr != nil {
			return protocol.ItemDescribeResponsePayload{}, auditErr
		}
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if !decision.Approved {
		if err := recordTerminalRequiredAudit(ctx, b.audit, audit.FromItemDescribeRequest(audit.EventApprovalDenied, correlation.RequestID, req)); err != nil {
			return protocol.ItemDescribeResponsePayload{}, err
		}
		return protocol.ItemDescribeResponsePayload{}, approval.DenialError(decision.DenialReason)
	}
	if err := b.ensureItemDescribeActive(itemCtx, req); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if err := recordRequiredAudit(itemCtx, b.audit, audit.FromItemDescribeRequest(audit.EventItemMetadataGranted, correlation.RequestID, req)); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if err := recordRequiredAudit(itemCtx, b.audit, audit.FromItemDescribeRequest(audit.EventItemMetadataFetchStarted, correlation.RequestID, req)); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	metadata, err := b.describeItem(itemCtx, req)
	if err != nil {
		failed := audit.FromItemDescribeRequest(audit.EventItemMetadataFetchFailed, correlation.RequestID, req)
		failed.ErrorCode = audit.ErrorCode(itemMetadataResolveErrorCode(err))
		if auditErr := recordTerminalRequiredAudit(ctx, b.audit, failed); auditErr != nil {
			return protocol.ItemDescribeResponsePayload{}, auditErr
		}
		return protocol.ItemDescribeResponsePayload{}, b.itemDescribeRequestError(itemCtx, req, err)
	}
	if err := b.ensureItemDescribeActive(itemCtx, req); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	if err := recordRequiredAudit(itemCtx, b.audit, audit.FromItemDescribeRequest(audit.EventItemMetadataFetchCompleted, correlation.RequestID, req)); err != nil {
		return protocol.ItemDescribeResponsePayload{}, err
	}
	return protocol.ItemDescribeResponsePayload{Item: metadata}, nil
}

func (b *Broker) describeItem(ctx context.Context, req request.ItemDescribeRequest) (itemmetadata.Metadata, error) {
	result := make(chan itemDescribeResult, 1)
	go func() {
		metadata, err := b.resolver.DescribeItem(ctx, req.Ref, req.Account)
		select {
		case result <- itemDescribeResult{metadata: metadata, err: err}:
		case <-ctx.Done():
		}
	}()

	select {
	case got := <-result:
		return got.metadata, got.err
	case <-ctx.Done():
		return itemmetadata.Metadata{}, contextCause(ctx)
	}
}

func (b *Broker) itemDescribeRequestError(
	ctx context.Context,
	req request.ItemDescribeRequest,
	err error,
) error {
	if activeErr := b.ensureItemDescribeActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, approval.ErrRequestExpired) {
			return activeErr
		}
	}
	return fmt.Errorf("%w: %w", ErrItemMetadataResolveFailed, err)
}

func (b *Broker) ensureItemDescribeActive(ctx context.Context, req request.ItemDescribeRequest) error {
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

func itemDescribeErrorEvent(requestID string, req request.ItemDescribeRequest, err error) audit.Event {
	if errors.Is(err, approval.ErrRequestExpired) {
		event := audit.FromItemDescribeRequest(audit.EventApprovalTimedOut, requestID, req)
		event.ErrorCode = audit.ErrorCode(protocol.ErrorCodeRequestExpired)
		return event
	}
	event := audit.FromItemDescribeRequest(audit.EventItemMetadataFetchFailed, requestID, req)
	event.ErrorCode = audit.ErrorCode(codeForItemDescribeError(err))
	return event
}

func codeForItemDescribeError(err error) protocol.ErrorCode {
	if errors.Is(err, context.Canceled) {
		return protocol.ErrorCodeContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return protocol.ErrorCodeContextDeadlineExceeded
	}
	return protocol.ErrorCodeRequestFailed
}

func (b *Broker) requestContext(ctx context.Context, expiresAt time.Time) (context.Context, context.CancelFunc) {
	ttl := expiresAt.Sub(b.now())
	deadlineCtx, cancelDeadline := context.WithTimeout(ctx, ttl)
	reqCtx, cancelReq := context.WithCancelCause(deadlineCtx)
	watcherDone := make(chan struct{})
	go func() {
		select {
		case <-b.stop:
			cancelReq(ErrDaemonStopped)
		case <-reqCtx.Done():
		case <-watcherDone:
		}
	}()

	return reqCtx, func() {
		close(watcherDone)
		cancelReq(context.Canceled)
		cancelDeadline()
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
	if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
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
	if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
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
	return resolveFailureErrorCode(err)
}

func itemMetadataResolveErrorCode(err error) protocol.ErrorCode {
	return resolveFailureErrorCode(err)
}

func resolveFailureErrorCode(err error) protocol.ErrorCode {
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
