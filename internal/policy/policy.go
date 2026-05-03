package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
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

const DefaultReusableUses = request.DefaultReusableUses

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
	random    io.Reader
	approvals map[string]*ReusableApproval
	sessions  map[string]*Session
}

type ReusableApproval struct {
	ID           string
	Nonce        string
	Key          ReuseKey
	ExpiresAt    time.Time
	MaxUses      int
	Uses         int
	ReservedUses int
}

type ReuseKey struct {
	Reason                 string
	Command                []string
	ResolvedExecutable     string
	ExecutableIdentity     fileidentity.Identity
	CWD                    string
	EnvironmentFingerprint string
	Secrets                []SecretGrant
	DeliveryMode           request.DeliveryMode
	TTL                    time.Duration
	ReusableUses           int
	OverrideEnv            bool
	OverriddenAliases      []string
	AllowMutableExecutable bool
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
		random:    rand.Reader,
		approvals: make(map[string]*ReusableApproval),
		sessions:  make(map[string]*Session),
	}
}

func (s *Store) AddReusable(req request.ExecRequest, id string, nonce string) (ReusableApproval, error) {
	return s.AddReusableWithLimit(req, request.ReusableUsesOrDefault(req.ReusableUses), id, nonce)
}

func (s *Store) AddReusableWithLimit(
	req request.ExecRequest,
	maxUses int,
	id string,
	nonce string,
) (ReusableApproval, error) {
	return s.addReusableWithLimit(req, maxUses, id, nonce, 0)
}

func (s *Store) AddReusableWithReservedUse(
	req request.ExecRequest,
	maxUses int,
	id string,
	nonce string,
) (ReusableApproval, error) {
	return s.addReusableWithLimit(req, maxUses, id, nonce, 1)
}

func (s *Store) addReusableWithLimit(
	req request.ExecRequest,
	maxUses int,
	id string,
	nonce string,
	reservedUses int,
) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	maxUses = request.ReusableUsesOrDefault(maxUses)
	if maxUses < 1 || maxUses > request.MaxReusableUses {
		return ReusableApproval{}, fmt.Errorf("%w: must be between 1 and %d", request.ErrInvalidReusableUses, request.MaxReusableUses)
	}
	if reservedUses < 0 || reservedUses > maxUses {
		return ReusableApproval{}, fmt.Errorf("%w: reserved uses must be between 0 and %d", ErrUseExhausted, maxUses)
	}
	req.ReusableUses = maxUses

	if id == "" {
		var err error
		id, err = s.randomID("appr")
		if err != nil {
			return ReusableApproval{}, fmt.Errorf("generate reusable approval id: %w", err)
		}
	}
	if nonce == "" {
		var err error
		nonce, err = s.randomID("nonce")
		if err != nil {
			return ReusableApproval{}, fmt.Errorf("generate reusable approval nonce: %w", err)
		}
	}

	approval := &ReusableApproval{
		ID:           id,
		Nonce:        nonce,
		Key:          NewReuseKey(req),
		ExpiresAt:    req.ExpiresAt,
		MaxUses:      maxUses,
		ReservedUses: reservedUses,
	}
	s.approvals[id] = approval

	return *approval, nil
}

func (s *Store) FindReusable(ctx context.Context, req request.ExecRequest, sink ReuseAuditSink) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, err := s.findReusableLocked(ctx, req, sink)
	if err != nil {
		if approval != nil {
			return *approval, err
		}
		return ReusableApproval{}, err
	}
	return *approval, nil
}

func (s *Store) ReserveReusable(ctx context.Context, req request.ExecRequest, sink ReuseAuditSink) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, err := s.findReusableLocked(ctx, req, sink)
	if err != nil {
		if approval != nil {
			return *approval, err
		}
		return ReusableApproval{}, err
	}
	approval.ReservedUses++
	return *approval, nil
}

func (s *Store) findReusableLocked(
	ctx context.Context,
	req request.ExecRequest,
	sink ReuseAuditSink,
) (*ReusableApproval, error) {
	key := NewReuseKey(req)
	now := s.now()
	var expired *ReusableApproval
	var exhausted *ReusableApproval
	for id, approval := range s.approvals {
		if !approval.Key.Equal(key) {
			continue
		}
		if !now.Before(approval.ExpiresAt) {
			snapshot := *approval
			delete(s.approvals, id)
			if expired == nil {
				expired = &snapshot
			}
			continue
		}
		remainingUses := approval.MaxUses - approval.Uses - approval.ReservedUses
		if remainingUses <= 0 {
			snapshot := *approval
			if approval.Uses >= approval.MaxUses && approval.ReservedUses == 0 {
				delete(s.approvals, id)
			}
			if exhausted == nil {
				exhausted = &snapshot
			}
			continue
		}

		event := ReuseAuditEvent{
			ApprovalID:   approval.ID,
			RemainingTTL: approval.ExpiresAt.Sub(now),
			RemainingUse: remainingUses,
		}
		if sink != nil {
			if err := sink.ApprovalReused(ctx, event); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrAuditFailed, err)
			}
		}

		return approval, nil
	}

	if expired != nil {
		return expired, ErrExpired
	}
	if exhausted != nil {
		return exhausted, ErrUseExhausted
	}
	return nil, ErrMismatch
}

func (s *Store) FinishReusableAttempt(id string, result DeliveryResult) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, ok := s.approvals[id]
	if !ok {
		return ReusableApproval{}, ErrMismatch
	}
	if !s.now().Before(approval.ExpiresAt) {
		delete(s.approvals, id)
		return *approval, ErrExpired
	}
	if consumesUse(result) {
		if approval.ReservedUses > 0 {
			approval.ReservedUses--
		}
		approval.Uses++
	} else if result == DeliveryPrePayloadFailure && approval.ReservedUses > 0 {
		approval.ReservedUses--
	}
	if approval.Uses >= approval.MaxUses && approval.ReservedUses == 0 {
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

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.approvals = make(map[string]*ReusableApproval)
	s.sessions = make(map[string]*Session)
}

func (s *Store) CreateSession(id string, nonce string, expiresAt time.Time, grants []SecretGrant, maxReads int) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxReads <= 0 {
		return Session{}, ErrReadExhausted
	}
	if id == "" {
		var err error
		id, err = s.randomID("sess")
		if err != nil {
			return Session{}, fmt.Errorf("generate session id: %w", err)
		}
	}
	if nonce == "" {
		var err error
		nonce, err = s.randomID("nonce")
		if err != nil {
			return Session{}, fmt.Errorf("generate session nonce: %w", err)
		}
	}

	handles := make(map[string]*Handle, len(grants))
	for _, grant := range grants {
		handleID, err := s.randomID("h")
		if err != nil {
			return Session{}, fmt.Errorf("generate secret handle id: %w", err)
		}
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
		Reason:                 req.Reason,
		Command:                slices.Clone(req.Command),
		ResolvedExecutable:     req.ResolvedExecutable,
		ExecutableIdentity:     req.ExecutableIdentity,
		CWD:                    req.CWD,
		EnvironmentFingerprint: req.EnvironmentFingerprint,
		Secrets:                secrets,
		DeliveryMode:           req.DeliveryMode,
		TTL:                    req.TTL,
		ReusableUses:           request.ReusableUsesOrDefault(req.ReusableUses),
		OverrideEnv:            req.OverrideEnv,
		OverriddenAliases:      overridden,
		AllowMutableExecutable: req.AllowMutableExecutable,
	}
}

func (k ReuseKey) Equal(other ReuseKey) bool {
	return k.Reason == other.Reason &&
		slices.Equal(k.Command, other.Command) &&
		k.ResolvedExecutable == other.ResolvedExecutable &&
		k.ExecutableIdentity == other.ExecutableIdentity &&
		k.CWD == other.CWD &&
		k.EnvironmentFingerprint == other.EnvironmentFingerprint &&
		slices.Equal(k.Secrets, other.Secrets) &&
		k.DeliveryMode == other.DeliveryMode &&
		k.TTL == other.TTL &&
		k.ReusableUses == other.ReusableUses &&
		k.OverrideEnv == other.OverrideEnv &&
		k.AllowMutableExecutable == other.AllowMutableExecutable &&
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

func (s *Store) randomID(prefix string) (string, error) {
	return randomID(s.random, prefix)
}

func randomID(reader io.Reader, prefix string) (string, error) {
	if reader == nil {
		reader = rand.Reader
	}
	var data [16]byte
	if _, err := io.ReadFull(reader, data[:]); err != nil {
		return "", fmt.Errorf("generate random id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(data[:]), nil
}
