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

func (m *reusableGrantManager) finishDelivery(approvalID string, result policy.DeliveryResult) error {
	if approvalID == "" {
		return nil
	}
	approval, err := m.store.FinishReusableAttempt(approvalID, result)
	if err != nil {
		if result == policy.DeliveryPayloadDelivered {
			m.clearScope(approvalID)
			if errors.Is(err, policy.ErrExpired) {
				return ErrRequestExpired
			}
			return err
		}
		if errors.Is(err, policy.ErrExpired) || errors.Is(err, policy.ErrUseExhausted) {
			m.clearScope(approvalID)
		}
		return nil
	}
	if approval.Uses >= approval.MaxUses {
		m.clearScope(approval.ID)
	}
	return nil
}

func (m *reusableGrantManager) rollbackApproval(approvalID string) {
	if approvalID == "" {
		return
	}
	m.store.RemoveReusable(approvalID)
	m.clearScope(approvalID)
}

func (m *reusableGrantManager) ensureApprovalActive(approvalID string, expiresAt time.Time) error {
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
		if err := m.ensureApprovalActive(approvalID, expiresAt); err != nil {
			return err
		}
		if err := m.cache.Put(approvalID, identity.ref, identity.account, value); err != nil {
			return fmt.Errorf("cache approved secret in locked memory: %w", err)
		}
	}
	if err := m.ensureApprovalActive(approvalID, expiresAt); err != nil {
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
