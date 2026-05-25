package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/gcpcompat"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretcache"
)

var (
	ErrAuditRequired              = errors.New("audit required")
	ErrMissingCache               = errors.New("approved secret cache entry missing")
	ErrNoReusableApproval         = errors.New("no reusable approval matches request")
	ErrNoResolver                 = errors.New("secret resolver unavailable")
	ErrSecretResolveFailed        = errors.New("secret resolve failed")
	ErrItemMetadataResolveFailed  = errors.New("item metadata resolve failed")
	ErrDaemonStopped              = errors.New("daemon stopped")
	ErrNoGCPTokenMinter           = errors.New("GCP token minter unavailable")
	ErrUnknownRequest             = errors.New("unknown request")
	ErrUnknownGCPSession          = errors.New("unknown GCP session")
	ErrGCPSessionExpired          = errors.New("GCP session expired")
	ErrGCPSessionNotUsableFromCWD = errors.New("GCP session is not usable from cwd")
	ErrGCPSessionExhausted        = errors.New("GCP session command starts exhausted")
)

type Resolver interface {
	Resolve(ctx context.Context, secret request.Secret) (string, error)
	DescribeItem(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error)
}

type AuditSink interface {
	Preflight(ctx context.Context) error
	Record(ctx context.Context, event audit.Event) error
}

type GCPTokenMinter interface {
	MintAccessToken(ctx context.Context, req GCPMintRequest) (gcpcompat.Token, error)
}

type GCPMintRequest struct {
	GoogleAccount  string
	Project        string
	ServiceAccount string
	Scopes         []string
	Lifetime       time.Duration
	Reason         string
}

type SecretCache interface {
	Put(key secretcache.CacheKey, value string) error
	Get(key secretcache.CacheKey) (string, bool)
	ClearScope(scopeID string)
	Clear()
}

type Broker struct {
	mu                    sync.Mutex
	now                   func() time.Time
	grants                *grantIssuer
	sessions              *sessionStore
	sessionPeerAuthorizer SessionPeerAuthorizer
	approver              approval.Approver
	resolver              Resolver
	gcpMinter             GCPTokenMinter
	gcpDeliveryBaseDir    string
	audit                 AuditSink
	active                map[string]*activeCommand
	gcpSessions           map[string]*gcpSession
	stopOnce              sync.Once
	stop                  chan struct{}
}

type activeKind string

const (
	activeKindExec          activeKind = "exec"
	activeKindGCPExec       activeKind = "gcp_exec"
	activeKindGCPSessionUse activeKind = "gcp_session_use"
)

type activeCommand struct {
	nonce    string
	kind     activeKind
	execReq  request.ExecRequest
	gcpReq   request.GCPExecRequest
	session  *gcpSessionCommandAudit
	started  bool
	childPID *int
	cleanup  func()
}

type gcpSession struct {
	handle          string
	auditID         string
	req             request.GCPSessionCreateRequest
	expiresAt       time.Time
	remainingStarts int
	token           *gcpSessionToken
}

type gcpSessionToken struct {
	env       map[string]string
	expiresAt time.Time
	lifetime  time.Duration
	cleanup   func()
}

type gcpSessionCommandAudit struct {
	SessionAuditID     string
	Reason             string
	ProfileName        string
	ProjectRoot        string
	Access             request.GCPAccess
	Command            []string
	ResolvedExecutable string
	CWD                string
	DeliveryMode       string
}

type itemDescribeResult struct {
	metadata itemmetadata.Metadata
	err      error
}

type Options struct {
	Now                   func() time.Time
	Store                 *policy.Store
	Cache                 SecretCache
	Approver              approval.Approver
	Resolver              Resolver
	GCPTokenMinter        GCPTokenMinter
	GCPDeliveryBaseDir    string
	Audit                 AuditSink
	FetchLimit            int
	SessionPeerAuthorizer SessionPeerAuthorizer
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
	sessionPeerAuthorizer := opts.SessionPeerAuthorizer
	if sessionPeerAuthorizer == nil {
		defaultAuthorizer := newProcessTreeSessionPeerAuthorizer()
		sessionPeerAuthorizer = defaultAuthorizer
	}
	broker := &Broker{
		now:                   now,
		sessionPeerAuthorizer: sessionPeerAuthorizer,
		approver:              opts.Approver,
		resolver:              opts.Resolver,
		gcpMinter:             opts.GCPTokenMinter,
		gcpDeliveryBaseDir:    opts.GCPDeliveryBaseDir,
		audit:                 opts.Audit,
		active:                make(map[string]*activeCommand),
		gcpSessions:           make(map[string]*gcpSession),
		stop:                  make(chan struct{}),
	}
	if broker.gcpMinter == nil {
		broker.gcpMinter = unavailableGCPTokenMinter{}
	}
	if broker.gcpDeliveryBaseDir == "" {
		broker.gcpDeliveryBaseDir = gcpcompat.DefaultBaseDir()
	}
	broker.sessions = newSessionStore(now, sessionPeerAuthorizer)
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

func (b *Broker) HandleSessionCreate(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.SessionCreateRequest,
	peer peercred.Info,
) (protocol.SessionCreateResponsePayload, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return protocol.SessionCreateResponsePayload{}, protocol.ErrInvalidNonce
	}
	if b.stopped() {
		return protocol.SessionCreateResponsePayload{}, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	peerBinding, err := b.sessionPeerAuthorizer.BindSessionPeer(peer, req.Binding)
	if err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	if req.Expired(b.now()) {
		return protocol.SessionCreateResponsePayload{}, approval.ErrRequestExpired
	}
	sessionCtx, cancelSession := b.requestContext(ctx, req.ExpiresAt)
	defer cancelSession()

	if err := recordRequiredAudit(sessionCtx, b.audit, audit.FromSessionCreateRequest(audit.EventApprovalRequested, correlation.RequestID, req)); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	decision, err := b.approver.Approve(sessionCtx, approval.NewSessionCreatePayload(correlation, req, peerBinding.Info()))
	if err != nil {
		if auditErr := b.recordSessionCreateApprovalError(ctx, correlation.RequestID, req, err); auditErr != nil {
			return protocol.SessionCreateResponsePayload{}, auditErr
		}
		return protocol.SessionCreateResponsePayload{}, err
	}
	if !decision.Approved {
		if err := b.recordSessionCreateDenied(ctx, correlation.RequestID, req); err != nil {
			return protocol.SessionCreateResponsePayload{}, err
		}
		return protocol.SessionCreateResponsePayload{}, approval.DenialError(decision.DenialReason)
	}
	if err := b.ensureSessionCreateActive(sessionCtx, req); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	if err := recordRequiredAudit(sessionCtx, b.audit, audit.FromSessionCreateRequest(audit.EventApprovalGranted, correlation.RequestID, req)); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	refValues, err := b.grants.resolveUniqueRefs(sessionCtx, correlation.RequestID, execRequestFromSessionCreate(req))
	if err != nil {
		return protocol.SessionCreateResponsePayload{}, b.grants.requestError(sessionCtx, execRequestFromSessionCreate(req), err)
	}
	if err := b.ensureSessionCreateActive(sessionCtx, req); err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	values := fanoutValues(req.Secrets, refValues)
	summary, err := b.sessions.create(req, values, peerBinding)
	if err != nil {
		return protocol.SessionCreateResponsePayload{}, err
	}
	event := audit.FromSessionCreateRequest(audit.EventSessionCreated, correlation.RequestID, req)
	event.SessionID = summary.SessionID
	event.RemainingReads = &summary.RemainingReads
	event.MaxReads = &summary.MaxReads
	if err := recordRequiredAudit(sessionCtx, b.audit, event); err != nil {
		b.sessions.destroy(summary.SessionID)
		return protocol.SessionCreateResponsePayload{}, err
	}
	return sessionCreatePayload(summary), nil
}

func (b *Broker) PrepareSessionResolve(
	ctx context.Context,
	correlation protocol.Correlation,
	req request.SessionResolveRequest,
	peer peercred.Info,
) (*SessionResolveDelivery, error) {
	if correlation.RequestID == "" || correlation.Nonce == "" {
		return nil, protocol.ErrInvalidNonce
	}
	if b.stopped() {
		return nil, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return nil, err
	}
	reservation, err := b.sessions.reserve(req, peer)
	if err != nil {
		return nil, err
	}
	activeReq := execRequestFromSessionResolve(req, reservation)
	if err := b.activateExec(correlation, activeReq); err != nil {
		b.sessions.finishReservation(reservation.SessionToken, false)
		return nil, err
	}
	delivery := &SessionResolveDelivery{
		broker:      b,
		correlation: correlation,
		req:         req,
		activeReq:   activeReq,
		reservation: reservation,
		payload: protocol.SessionResolveResponsePayload{
			Env:           reservation.Env,
			SecretAliases: reservation.SecretAliases,
			OverrideEnv:   reservation.OverrideEnv,
		},
	}
	return delivery, nil
}

type SessionResolveDelivery struct {
	broker       *Broker
	correlation  protocol.Correlation
	req          request.SessionResolveRequest
	activeReq    request.ExecRequest
	reservation  sessionReservation
	payload      protocol.SessionResolveResponsePayload
	finalizeOnce sync.Once
}

func (d *SessionResolveDelivery) Payload() protocol.SessionResolveResponsePayload {
	return d.payload
}

func (d *SessionResolveDelivery) ExpiresAt() time.Time {
	return d.reservation.ExpiresAt
}

func (d *SessionResolveDelivery) BeforeWrite(ctx context.Context) error {
	event := audit.FromSessionResolveRequest(
		audit.EventSessionResolved,
		d.correlation.RequestID,
		d.req,
		auditRefsForIdentities(d.reservation.Secrets, uniqueSecretIdentities(d.reservation.Secrets)),
	)
	event.SessionID = d.reservation.SessionID
	event.RemainingReads = &d.reservation.RemainingReads
	event.MaxReads = &d.reservation.MaxReads
	if err := recordRequiredAudit(ctx, d.broker.audit, event); err != nil {
		return err
	}
	if err := recordRequiredAudit(ctx, d.broker.audit, audit.FromExecRequest(audit.EventCommandStarting, d.correlation.RequestID, d.activeReq)); err != nil {
		return err
	}
	return nil
}

func (d *SessionResolveDelivery) CommitDelivered() {
	d.finalizeOnce.Do(func() {
		d.broker.sessions.finishReservation(d.reservation.SessionToken, true)
	})
}

func (d *SessionResolveDelivery) AbortBeforePayload() {
	d.finalizeOnce.Do(func() {
		d.broker.deactivateExec(d.correlation)
		d.broker.sessions.finishReservation(d.reservation.SessionToken, false)
	})
}

func (b *Broker) HandleSessionDestroy(ctx context.Context, req request.SessionDestroyRequest) (protocol.SessionDestroyResponsePayload, error) {
	if b.stopped() {
		return protocol.SessionDestroyResponsePayload{}, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.SessionDestroyResponsePayload{}, err
	}
	if req.All {
		count := b.sessions.destroyAll()
		event := audit.Event{
			Type: audit.EventSessionDestroyed,
		}
		if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
			return protocol.SessionDestroyResponsePayload{}, err
		}
		return protocol.SessionDestroyResponsePayload{Destroyed: true, DestroyedCount: count}, nil
	}

	destroyed := b.sessions.destroy(req.SessionID)
	event := audit.Event{
		Type:      audit.EventSessionDestroyed,
		SessionID: req.SessionID,
	}
	if !destroyed {
		event.ErrorCode = audit.ErrorCode(protocol.ErrorCodeSessionNotFound)
	}
	if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
		return protocol.SessionDestroyResponsePayload{}, err
	}
	if !destroyed {
		return protocol.SessionDestroyResponsePayload{}, ErrSessionNotFound
	}
	return protocol.SessionDestroyResponsePayload{SessionID: req.SessionID, Destroyed: true}, nil
}

func (b *Broker) HandleSessionList(ctx context.Context) (protocol.SessionListResponsePayload, error) {
	if b.stopped() {
		return protocol.SessionListResponsePayload{}, ErrDaemonStopped
	}
	if err := preflightRequiredAudit(ctx, b.audit); err != nil {
		return protocol.SessionListResponsePayload{}, err
	}
	summaries := b.sessions.list()
	sessions := make([]protocol.SessionInfoPayload, 0, len(summaries))
	for _, summary := range summaries {
		sessions = append(sessions, sessionInfoPayload(summary))
	}
	return protocol.SessionListResponsePayload{Sessions: sessions}, nil
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
		err = b.itemDescribeApprovalError(itemCtx, req, err)
		if shouldAuditItemDescribeApprovalError(err) {
			if auditErr := recordTerminalRequiredAudit(ctx, b.audit, itemDescribeErrorEvent(correlation.RequestID, req, err)); auditErr != nil {
				return protocol.ItemDescribeResponsePayload{}, auditErr
			}
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

func (b *Broker) itemDescribeApprovalError(ctx context.Context, req request.ItemDescribeRequest, err error) error {
	if errors.Is(err, approval.ErrRequestExpired) || errors.Is(err, approval.ErrApprovalDenied) {
		return err
	}
	if activeErr := b.ensureItemDescribeActive(ctx, req); activeErr != nil {
		if errors.Is(activeErr, ErrDaemonStopped) || errors.Is(activeErr, approval.ErrRequestExpired) {
			return activeErr
		}
	}
	return err
}

func shouldAuditItemDescribeApprovalError(err error) bool {
	return !errors.Is(err, ErrDaemonStopped)
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
	if errors.Is(err, ErrDaemonStopped) {
		return protocol.ErrorCodeDaemonStopped
	}
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
	b.active[correlation.RequestID] = &activeCommand{
		nonce:   correlation.Nonce,
		kind:    activeKindExec,
		execReq: req,
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

	event := active.commandStartedEvent(correlation.RequestID)
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

	event := active.commandCompletedEvent(correlation.RequestID)
	event.ExitCode = new(exitCode)
	event.Signal = signal
	if err := recordRequiredAudit(ctx, b.audit, event); err != nil {
		return err
	}

	b.mu.Lock()
	if active.cleanup != nil {
		active.cleanup()
	}
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
	event := active.disconnectedEvent(eventType, requestID)
	event.ChildPID = active.childPID
	if active.cleanup != nil {
		active.cleanup()
	}
	b.recordBestEffortAudit(ctx, event)
}

func (b *Broker) StopWithAuditEvent(ctx context.Context, event audit.Event) {
	b.stopOnce.Do(func() { close(b.stop) })
	b.RecordStopAttempt(ctx, event)
	b.mu.Lock()
	for _, active := range b.active {
		if active.cleanup != nil {
			active.cleanup()
		}
	}
	for _, session := range b.gcpSessions {
		session.cleanup()
	}
	b.active = make(map[string]*activeCommand)
	b.gcpSessions = make(map[string]*gcpSession)
	b.mu.Unlock()
	b.grants.clearReusableGrants()
	b.sessions.clear()
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

func (b *Broker) activeRequest(correlation protocol.Correlation) (*activeCommand, error) {
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

func (active *activeCommand) commandStartedEvent(requestID string) audit.Event {
	switch active.kind {
	case activeKindExec:
		return audit.FromExecRequest(audit.EventCommandStarted, requestID, active.execReq)
	case activeKindGCPExec:
		return audit.FromGCPExecRequest(audit.EventCommandStarted, requestID, active.gcpReq)
	case activeKindGCPSessionUse:
		return audit.FromGCPSessionCommand(audit.EventCommandStarted, requestID, *active.session)
	default:
		return audit.FromExecRequest(audit.EventCommandStarted, requestID, active.execReq)
	}
}

func (active *activeCommand) commandCompletedEvent(requestID string) audit.Event {
	switch active.kind {
	case activeKindExec:
		return audit.FromExecRequest(audit.EventCommandCompleted, requestID, active.execReq)
	case activeKindGCPExec:
		return audit.FromGCPExecRequest(audit.EventCommandCompleted, requestID, active.gcpReq)
	case activeKindGCPSessionUse:
		return audit.FromGCPSessionCommand(audit.EventCommandCompleted, requestID, *active.session)
	default:
		return audit.FromExecRequest(audit.EventCommandCompleted, requestID, active.execReq)
	}
}

func (active *activeCommand) disconnectedEvent(eventType audit.EventType, requestID string) audit.Event {
	switch active.kind {
	case activeKindExec:
		return audit.FromExecRequest(eventType, requestID, active.execReq)
	case activeKindGCPExec:
		return audit.FromGCPExecRequest(eventType, requestID, active.gcpReq)
	case activeKindGCPSessionUse:
		return audit.FromGCPSessionCommand(eventType, requestID, *active.session)
	default:
		return audit.FromExecRequest(eventType, requestID, active.execReq)
	}
}

func (b *Broker) stopped() bool {
	select {
	case <-b.stop:
		return true
	default:
		return false
	}
}

func (b *Broker) ensureSessionCreateActive(ctx context.Context, req request.SessionCreateRequest) error {
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

func (b *Broker) recordSessionCreateApprovalError(
	ctx context.Context,
	requestID string,
	req request.SessionCreateRequest,
	err error,
) error {
	if errors.Is(err, approval.ErrRequestExpired) {
		event := audit.FromSessionCreateRequest(audit.EventApprovalTimedOut, requestID, req)
		event.ErrorCode = auditErrorCode(protocol.ErrorCodeRequestExpired)
		return recordTerminalRequiredAudit(ctx, b.audit, event)
	}
	return nil
}

func (b *Broker) recordSessionCreateDenied(ctx context.Context, requestID string, req request.SessionCreateRequest) error {
	event := audit.FromSessionCreateRequest(audit.EventApprovalDenied, requestID, req)
	event.ErrorCode = auditErrorCode(protocol.ErrorCodeApprovalDenied)
	return recordTerminalRequiredAudit(ctx, b.audit, event)
}

func execRequestFromSessionCreate(req request.SessionCreateRequest) request.ExecRequest {
	return request.ExecRequest{
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		ResolvedExecutable: req.ResolvedExecutable,
		ExecutableIdentity: req.ExecutableIdentity,
		CWD:                req.CWD,
		Secrets:            slices.Clone(req.Secrets),
		TTL:                req.TTL,
		ReceivedAt:         req.ReceivedAt,
		ExpiresAt:          req.ExpiresAt,
		OverrideEnv:        req.OverrideEnv,
	}
}

func execRequestFromSessionResolve(req request.SessionResolveRequest, reservation sessionReservation) request.ExecRequest {
	return request.ExecRequest{
		Reason:                 reservation.Reason,
		Command:                slices.Clone(req.Command),
		ResolvedExecutable:     req.ResolvedExecutable,
		ExecutableIdentity:     req.ExecutableIdentity,
		CWD:                    req.CWD,
		EnvironmentFingerprint: req.EnvironmentFingerprint,
		Secrets:                slices.Clone(reservation.Secrets),
		TTL:                    time.Until(reservation.ExpiresAt),
		ReceivedAt:             time.Now(),
		ExpiresAt:              reservation.ExpiresAt,
		OverrideEnv:            reservation.OverrideEnv,
	}
}

func sessionCreatePayload(summary request.SessionSummary) protocol.SessionCreateResponsePayload {
	return protocol.SessionCreateResponsePayload{
		SessionID:      summary.SessionID,
		SessionToken:   summary.SessionToken,
		SecretAliases:  slices.Clone(summary.SecretAliases),
		ExpiresAt:      summary.ExpiresAt,
		MaxReads:       summary.MaxReads,
		RemainingReads: summary.RemainingReads,
		Binding:        summary.Binding,
	}
}

func sessionInfoPayload(summary request.SessionSummary) protocol.SessionInfoPayload {
	return protocol.SessionInfoPayload{
		SessionID:      summary.SessionID,
		Reason:         summary.Reason,
		CWD:            summary.CWD,
		SecretAliases:  slices.Clone(summary.SecretAliases),
		ExpiresAt:      summary.ExpiresAt,
		MaxReads:       summary.MaxReads,
		RemainingReads: summary.RemainingReads,
		OverrideEnv:    summary.OverrideEnv,
		Binding:        summary.Binding,
	}
}
