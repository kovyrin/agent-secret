package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

type reusableGrantManager struct {
	mu      sync.Mutex
	now     func() time.Time
	store   *policy.Store
	cache   SecretCache
	expiry  map[string]*time.Timer
	stopped func() bool
}

type reusableRefreshResolver func(policy.ReusableApproval) (map[secretIdentity]string, error)
type reusableRefreshAudit func(policy.ReusableApproval) error
type reusableGrantLiveness func(policy.ReusableApproval) error

func newReusableGrantManager(
	now func() time.Time,
	store *policy.Store,
	cache SecretCache,
	stopped func() bool,
) *reusableGrantManager {
	if stopped == nil {
		stopped = func() bool { return false }
	}
	return &reusableGrantManager{
		now:     now,
		store:   store,
		cache:   cache,
		expiry:  make(map[string]*time.Timer),
		stopped: stopped,
	}
}

func (m *reusableGrantManager) clear() {
	m.mu.Lock()
	for id, timer := range m.expiry {
		timer.Stop()
		delete(m.expiry, id)
	}
	m.mu.Unlock()
	m.cache.Clear()
	m.store.Clear()
}

func (m *reusableGrantManager) reserve(
	ctx context.Context,
	req request.ExecRequest,
	sink policy.ReuseAuditSink,
) (policy.ReusableApproval, error) {
	approval, err := m.store.ReserveReusable(ctx, req, sink)
	if err != nil {
		if errors.Is(err, policy.ErrAuditFailed) {
			return policy.ReusableApproval{}, err
		}
		if approval.ID != "" && errors.Is(err, policy.ErrExpired) {
			m.clearScope(approval.ID)
		}
		if approval.ID != "" &&
			errors.Is(err, policy.ErrUseExhausted) &&
			approval.Uses >= approval.MaxUses &&
			approval.ReservedUses == 0 {
			m.clearScope(approval.ID)
		}
		return policy.ReusableApproval{}, nil
	}
	return approval, nil
}

func (m *reusableGrantManager) finishPayloadDelivered(approvalID string) error {
	approval, err := m.store.FinishReusableAttempt(approvalID, policy.DeliveryPayloadDelivered)
	if err != nil {
		m.clearScope(approvalID)
		if errors.Is(err, policy.ErrExpired) {
			return ErrRequestExpired
		}
		return err
	}
	if approval.Uses >= approval.MaxUses {
		m.clearScope(approval.ID)
	}
	return nil
}

func (m *reusableGrantManager) finishPrePayloadFailure(approvalID string) {
	if approvalID == "" {
		return
	}
	if _, err := m.store.FinishReusableAttempt(approvalID, policy.DeliveryPrePayloadFailure); err != nil {
		if errors.Is(err, policy.ErrExpired) || errors.Is(err, policy.ErrUseExhausted) {
			m.clearScope(approvalID)
		}
	}
}

func (m *reusableGrantManager) rollbackApproval(approvalID string) {
	if approvalID == "" {
		return
	}
	m.store.RemoveReusable(approvalID)
	m.clearScope(approvalID)
}

func (m *reusableGrantManager) rollbackGrant(grant ExecGrant) {
	if grant.reusableMutationID != "" {
		m.rollbackApproval(grant.reusableMutationID)
		return
	}
	m.releaseReservation(grant.ApprovalID)
}

func (m *reusableGrantManager) releaseReservation(approvalID string) {
	m.finishPrePayloadFailure(approvalID)
}

func (m *reusableGrantManager) active(approvalID string, expiresAt time.Time) error {
	if approvalID == "" || expiresAt.IsZero() {
		return nil
	}
	if m.stopped() {
		m.rollbackApproval(approvalID)
		return ErrDaemonStopped
	}
	if m.now().Before(expiresAt) {
		return nil
	}
	m.rollbackApproval(approvalID)
	return ErrRequestExpired
}

func (m *reusableGrantManager) scheduleExpiry(approvalID string, expiresAt time.Time) {
	ttl := expiresAt.Sub(m.now())
	if ttl <= 0 {
		m.store.RemoveReusable(approvalID)
		m.clearScope(approvalID)
		return
	}

	m.mu.Lock()
	if previous := m.expiry[approvalID]; previous != nil {
		previous.Stop()
	}
	timer := time.AfterFunc(ttl, func() {
		m.store.RemoveReusable(approvalID)
		m.clearScope(approvalID)
	})
	m.expiry[approvalID] = timer
	m.mu.Unlock()
}

func (m *reusableGrantManager) clearScope(approvalID string) {
	m.mu.Lock()
	if timer := m.expiry[approvalID]; timer != nil {
		timer.Stop()
		delete(m.expiry, approvalID)
	}
	m.mu.Unlock()
	m.cache.ClearScope(approvalID)
}

func (m *reusableGrantManager) cacheResolvedValues(
	approvalID string,
	expiresAt time.Time,
	refValues map[secretIdentity]string,
) error {
	for identity, value := range refValues {
		if err := m.active(approvalID, expiresAt); err != nil {
			return err
		}
		if err := m.cache.Put(approvalID, identity.ref, identity.account, value); err != nil {
			return fmt.Errorf("cache approved secret in locked memory: %w", err)
		}
	}
	if err := m.active(approvalID, expiresAt); err != nil {
		return err
	}
	return nil
}

func (m *reusableGrantManager) cachedValues(
	approvalID string,
	secrets []request.Secret,
) (map[string]string, error) {
	env := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		value, ok := m.cache.Get(approvalID, secret.Ref.Raw, secret.Account)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingCache, secret.Ref.Raw)
		}
		env[secret.Alias] = value
	}
	return env, nil
}

func (m *reusableGrantManager) tryGrant(
	ctx context.Context,
	req request.ExecRequest,
	audit policy.ReuseAuditSink,
	refresh reusableRefreshResolver,
	recordRefresh reusableRefreshAudit,
	ensureActive reusableGrantLiveness,
) (ExecGrant, error) {
	approval, err := m.reserve(ctx, req, audit)
	if err != nil {
		return ExecGrant{}, err
	}
	if approval.ID == "" {
		return ExecGrant{}, nil
	}
	delivered := false
	defer func() {
		if !delivered {
			m.releaseReservation(approval.ID)
		}
	}()
	if err := ensureActive(approval); err != nil {
		return ExecGrant{}, err
	}

	var values map[string]string
	if req.ForceRefresh {
		refValues, err := refresh(approval)
		if err != nil {
			return ExecGrant{}, err
		}
		values, err = m.refreshedValues(approval, req, refValues, recordRefresh, ensureActive)
		if err != nil {
			return ExecGrant{}, err
		}
	} else {
		values, err = m.cachedValues(approval.ID, req.Secrets)
		if err != nil {
			return ExecGrant{}, err
		}
	}
	if err := ensureActive(approval); err != nil {
		return ExecGrant{}, err
	}

	delivered = true
	return ExecGrant{
		Env:                values,
		SecretAliases:      aliases(req.Secrets),
		ApprovalID:         approval.ID,
		reusableMutationID: reusableMutationID(req.ForceRefresh, approval.ID),
		approvalExpiresAt:  approval.ExpiresAt,
	}, nil
}

func (m *reusableGrantManager) refreshedValues(
	approval policy.ReusableApproval,
	req request.ExecRequest,
	refValues map[secretIdentity]string,
	recordRefresh reusableRefreshAudit,
	ensureActive reusableGrantLiveness,
) (map[string]string, error) {
	if err := ensureActive(approval); err != nil {
		return nil, err
	}
	values := fanoutValues(req.Secrets, refValues)
	if err := m.cacheResolvedValues(approval.ID, approval.ExpiresAt, refValues); err != nil {
		m.rollbackApproval(approval.ID)
		return nil, err
	}
	if err := recordRefresh(approval); err != nil {
		m.rollbackApproval(approval.ID)
		return nil, err
	}
	if err := ensureActive(approval); err != nil {
		m.rollbackApproval(approval.ID)
		return nil, err
	}
	return values, nil
}

func (m *reusableGrantManager) createGrant(
	req request.ExecRequest,
	decision ApprovalDecision,
	refValues map[secretIdentity]string,
) (string, time.Time, error) {
	if !decision.Reusable {
		return "", time.Time{}, nil
	}
	approval, err := m.store.AddReusableWithReservedUse(req, decision.ReusableUses, "", "")
	if err != nil {
		return "", time.Time{}, err
	}
	if err := m.cacheResolvedValues(approval.ID, approval.ExpiresAt, refValues); err != nil {
		m.rollbackApproval(approval.ID)
		return "", time.Time{}, err
	}
	m.scheduleExpiry(approval.ID, approval.ExpiresAt)
	return approval.ID, approval.ExpiresAt, nil
}
