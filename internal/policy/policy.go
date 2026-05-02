package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretmem"
)

var (
	ErrAuditFailed   = errors.New("audit failed")
	ErrDestroyed     = errors.New("policy object destroyed")
	ErrExpired       = errors.New("policy object expired")
	ErrHandleMissing = errors.New("capability handle missing")
	ErrMismatch      = errors.New("policy mismatch")
	ErrReadExhausted = errors.New("capability read count exhausted")
	ErrUseExhausted  = errors.New("reusable approval use count exhausted")
)

const DefaultReusableUses = 3

type ReuseAuditSink interface {
	ApprovalReused(ctx context.Context, event ReuseAuditEvent) error
}

type ReuseAuditEvent struct {
	ApprovalID   string
	RemainingTTL time.Duration
	RemainingUse int
}

type Store struct {
	mu        sync.Mutex
	now       func() time.Time
	approvals map[string]*ReusableApproval
	sessions  map[string]*Session
}

type ReusableApproval struct {
	ID        string
	Nonce     string
	Key       ReuseKey
	ExpiresAt time.Time
	MaxUses   int
	Uses      int
}

type ReuseKey struct {
	Reason             string
	Command            []string
	ResolvedExecutable string
	CWD                string
	Secrets            []SecretGrant
	DeliveryMode       request.DeliveryMode
	TTL                time.Duration
	OverrideEnv        bool
	OverriddenAliases  []string
}

type SecretGrant struct {
	Alias   string
	Ref     string
	Account string
}

type Session struct {
	ID        string
	Nonce     string
	ExpiresAt time.Time
	Destroyed bool
	Handles   map[string]*Handle
}

type Handle struct {
	ID       string
	Alias    string
	Ref      string
	Account  string
	MaxReads int
	Reads    int
}

type DeliveryResult string

const (
	DeliveryPrePayloadFailure               DeliveryResult = "pre_payload_failure"
	DeliveryPayloadDelivered                DeliveryResult = "payload_delivered"
	DeliveryCLISpawnFailureAfterPayload     DeliveryResult = "cli_spawn_failure_after_payload"
	DeliveryImmediateChildExitAfterPayload  DeliveryResult = "immediate_child_exit_after_payload"
	DeliveryNonZeroChildExitAfterPayload    DeliveryResult = "non_zero_child_exit_after_payload"
	DeliveryCommandStartedAuditFailureAfter DeliveryResult = "command_started_audit_failure_after_payload"
	DeliveryClientDisconnectAfterPayload    DeliveryResult = "client_disconnect_after_payload"
)

func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}

	return &Store{
		now:       now,
		approvals: make(map[string]*ReusableApproval),
		sessions:  make(map[string]*Session),
	}
}

func (s *Store) AddReusable(req request.ExecRequest, id string, nonce string) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "" {
		id = randomID("appr")
	}
	if nonce == "" {
		nonce = randomID("nonce")
	}

	approval := &ReusableApproval{
		ID:        id,
		Nonce:     nonce,
		Key:       NewReuseKey(req),
		ExpiresAt: req.ExpiresAt,
		MaxUses:   DefaultReusableUses,
	}
	s.approvals[id] = approval

	return *approval, nil
}

func (s *Store) FindReusable(ctx context.Context, req request.ExecRequest, sink ReuseAuditSink) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := NewReuseKey(req)
	now := s.now()
	for id, approval := range s.approvals {
		if !approval.Key.Equal(key) {
			continue
		}
		if !now.Before(approval.ExpiresAt) {
			delete(s.approvals, id)
			return *approval, ErrExpired
		}
		remainingUses := approval.MaxUses - approval.Uses
		if remainingUses <= 0 {
			delete(s.approvals, id)
			return *approval, ErrUseExhausted
		}

		event := ReuseAuditEvent{
			ApprovalID:   approval.ID,
			RemainingTTL: approval.ExpiresAt.Sub(now),
			RemainingUse: remainingUses,
		}
		if sink != nil {
			if err := sink.ApprovalReused(ctx, event); err != nil {
				return ReusableApproval{}, fmt.Errorf("%w: %w", ErrAuditFailed, err)
			}
		}

		return *approval, nil
	}

	return ReusableApproval{}, ErrMismatch
}

func (s *Store) FinishReusableAttempt(id string, result DeliveryResult) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, ok := s.approvals[id]
	if !ok {
		return ReusableApproval{}, ErrMismatch
	}
	if consumesUse(result) {
		approval.Uses++
	}
	if approval.Uses >= approval.MaxUses {
		delete(s.approvals, id)
	}

	return *approval, nil
}

func (s *Store) RemoveReusable(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.approvals[id]; !ok {
		return false
	}
	delete(s.approvals, id)
	return true
}

func (s *Store) CreateSession(id string, nonce string, expiresAt time.Time, grants []SecretGrant, maxReads int) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == "" {
		id = randomID("sess")
	}
	if nonce == "" {
		nonce = randomID("nonce")
	}
	if maxReads <= 0 {
		return Session{}, ErrReadExhausted
	}

	handles := make(map[string]*Handle, len(grants))
	for _, grant := range grants {
		handleID := randomID("h")
		handles[handleID] = &Handle{
			ID:       handleID,
			Alias:    grant.Alias,
			Ref:      grant.Ref,
			Account:  grant.Account,
			MaxReads: maxReads,
		}
	}

	session := &Session{
		ID:        id,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
		Handles:   handles,
	}
	s.sessions[id] = session

	return cloneSession(session), nil
}

func (s *Store) ResolveHandle(sessionID string, handleID string, nonce string) (SecretGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return SecretGrant{}, ErrMismatch
	}
	if session.Destroyed {
		return SecretGrant{}, ErrDestroyed
	}
	if session.Nonce != nonce {
		return SecretGrant{}, ErrMismatch
	}
	if !s.now().Before(session.ExpiresAt) {
		return SecretGrant{}, ErrExpired
	}

	handle, ok := session.Handles[handleID]
	if !ok {
		return SecretGrant{}, ErrHandleMissing
	}
	if handle.Reads >= handle.MaxReads {
		return SecretGrant{}, ErrReadExhausted
	}

	handle.Reads++
	return SecretGrant{Alias: handle.Alias, Ref: handle.Ref, Account: handle.Account}, nil
}

func (s *Store) DestroySession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return ErrMismatch
	}
	session.Destroyed = true
	return nil
}

func NewReuseKey(req request.ExecRequest) ReuseKey {
	secrets := make([]SecretGrant, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		secrets = append(secrets, SecretGrant{Alias: secret.Alias, Ref: secret.Ref.Raw, Account: secret.Account})
	}
	slices.SortFunc(secrets, func(a SecretGrant, b SecretGrant) int {
		if a.Alias < b.Alias {
			return -1
		}
		if a.Alias > b.Alias {
			return 1
		}
		if a.Ref < b.Ref {
			return -1
		}
		if a.Ref > b.Ref {
			return 1
		}
		if a.Account < b.Account {
			return -1
		}
		if a.Account > b.Account {
			return 1
		}
		return 0
	})

	overridden := slices.Clone(req.OverriddenAliases)
	slices.Sort(overridden)

	return ReuseKey{
		Reason:             req.Reason,
		Command:            slices.Clone(req.Command),
		ResolvedExecutable: req.ResolvedExecutable,
		CWD:                req.CWD,
		Secrets:            secrets,
		DeliveryMode:       req.DeliveryMode,
		TTL:                req.TTL,
		OverrideEnv:        req.OverrideEnv,
		OverriddenAliases:  overridden,
	}
}

func (k ReuseKey) Equal(other ReuseKey) bool {
	return k.Reason == other.Reason &&
		slices.Equal(k.Command, other.Command) &&
		k.ResolvedExecutable == other.ResolvedExecutable &&
		k.CWD == other.CWD &&
		slices.Equal(k.Secrets, other.Secrets) &&
		k.DeliveryMode == other.DeliveryMode &&
		k.TTL == other.TTL &&
		k.OverrideEnv == other.OverrideEnv &&
		slices.Equal(k.OverriddenAliases, other.OverriddenAliases)
}

type SecretCache struct {
	mu     sync.Mutex
	values map[CacheKey]*secretmem.Value
}

type CacheKey struct {
	ScopeID string
	Ref     string
	Account string
}

func NewSecretCache() *SecretCache {
	return &SecretCache{values: make(map[CacheKey]*secretmem.Value)}
}

func (c *SecretCache) Put(scopeID string, ref string, account string, value string) error {
	lockedValue, err := secretmem.New(value)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	key := CacheKey{ScopeID: scopeID, Ref: ref, Account: account}
	if oldValue := c.values[key]; oldValue != nil {
		_ = oldValue.Destroy()
	}
	c.values[key] = lockedValue
	return nil
}

func (c *SecretCache) Get(scopeID string, ref string, account string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.values[CacheKey{ScopeID: scopeID, Ref: ref, Account: account}]
	if !ok {
		return "", false
	}
	resolved, err := value.String()
	if err != nil {
		return "", false
	}
	return resolved, true
}

func (c *SecretCache) ClearScope(scopeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.values {
		if key.ScopeID == scopeID {
			_ = c.values[key].Destroy()
			delete(c.values, key)
		}
	}
}

func (c *SecretCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, value := range c.values {
		_ = value.Destroy()
		delete(c.values, key)
	}
}

func consumesUse(result DeliveryResult) bool {
	switch result {
	case DeliveryPayloadDelivered,
		DeliveryCLISpawnFailureAfterPayload,
		DeliveryImmediateChildExitAfterPayload,
		DeliveryNonZeroChildExitAfterPayload,
		DeliveryCommandStartedAuditFailureAfter,
		DeliveryClientDisconnectAfterPayload:
		return true
	case DeliveryPrePayloadFailure:
		return false
	default:
		return false
	}
}

func cloneSession(session *Session) Session {
	clone := *session
	clone.Handles = make(map[string]*Handle, len(session.Handles))
	for id, handle := range session.Handles {
		handleClone := *handle
		clone.Handles[id] = &handleClone
	}
	return clone
}

func randomID(prefix string) string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(fmt.Sprintf("generate random id: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(data[:])
}
