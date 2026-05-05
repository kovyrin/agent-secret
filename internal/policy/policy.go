package policy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
	"github.com/kovyrin/agent-secret/internal/randid"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrExpired               = errors.New("policy object expired")
	ErrMismatch              = errors.New("policy mismatch")
	ErrUseExhausted          = errors.New("reusable approval use count exhausted")
	ErrInvalidDeliveryResult = errors.New("invalid reusable approval delivery result")
)

const DefaultReusableUses = request.DefaultReusableUses

type ReuseMetadata struct {
	ApprovalID    string
	RemainingTTL  time.Duration
	RemainingUses int
}

type Store struct {
	mu        sync.Mutex
	now       func() time.Time
	random    io.Reader
	approvals map[string]*ReusableApproval
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

// ReusableApprovalError wraps ErrExpired or ErrUseExhausted with the stale
// approval snapshot that caused the failure.
type ReusableApprovalError struct {
	Approval ReusableApproval
	Err      error
}

func (e *ReusableApprovalError) Error() string {
	return e.Err.Error()
}

func (e *ReusableApprovalError) Unwrap() error {
	return e.Err
}

// ReusableApprovalFromError extracts a stale reusable approval snapshot from err.
func ReusableApprovalFromError(err error) (ReusableApproval, bool) {
	var approvalErr *ReusableApprovalError
	if errors.As(err, &approvalErr) {
		return approvalErr.Approval, true
	}
	return ReusableApproval{}, false
}

type ReusableApprovalSpec struct {
	Request      request.ExecRequest
	ID           string
	Nonce        string
	MaxUses      int
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
	TTL                    time.Duration
	ReusableUses           int
	OverrideEnv            bool
	OverriddenAliases      []string
}

type SecretGrant struct {
	Alias   string
	Ref     string
	Account string
}

type DeliveryResult string

const (
	DeliveryPrePayloadFailure DeliveryResult = "pre_payload_failure"
	DeliveryPayloadDelivered  DeliveryResult = "payload_delivered"
)

func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}

	return &Store{
		now:       now,
		random:    rand.Reader,
		approvals: make(map[string]*ReusableApproval),
	}
}

func (s *Store) AddReusable(spec ReusableApprovalSpec) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req := spec.Request
	maxUses := spec.MaxUses
	if maxUses == 0 {
		maxUses = req.ReusableUses
	}
	maxUses = request.ReusableUsesOrDefault(maxUses)
	if maxUses < 1 || maxUses > request.MaxReusableUses {
		return ReusableApproval{}, fmt.Errorf("%w: must be between 1 and %d", request.ErrInvalidReusableUses, request.MaxReusableUses)
	}
	reservedUses := spec.ReservedUses
	if reservedUses < 0 || reservedUses > maxUses {
		return ReusableApproval{}, fmt.Errorf("%w: reserved uses must be between 0 and %d", ErrUseExhausted, maxUses)
	}
	req.ReusableUses = maxUses

	id := spec.ID
	if id == "" {
		var err error
		id, err = s.randomID("appr")
		if err != nil {
			return ReusableApproval{}, fmt.Errorf("generate reusable approval id: %w", err)
		}
	}
	nonce := spec.Nonce
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

// MatchReusable finds a reusable approval and prunes stale matches.
//
// Expired or exhausted matches are reported as ErrExpired or ErrUseExhausted
// wrapped in ReusableApprovalError so callers can inspect the stale approval
// snapshot without treating a non-zero normal return as successful.
func (s *Store) MatchReusable(req request.ExecRequest) (ReusableApproval, ReuseMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, metadata, err := s.findReusableLocked(req)
	if err != nil {
		return ReusableApproval{}, ReuseMetadata{}, reusableApprovalError(approval, err)
	}
	return *approval, metadata, nil
}

// ReserveReusable reserves one use from a live reusable approval.
//
// Expired or exhausted matches are reported as ErrExpired or ErrUseExhausted
// wrapped in ReusableApprovalError so callers can inspect the stale approval
// snapshot without treating a non-zero normal return as successful.
func (s *Store) ReserveReusable(req request.ExecRequest) (ReusableApproval, ReuseMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, metadata, err := s.findReusableLocked(req)
	if err != nil {
		return ReusableApproval{}, ReuseMetadata{}, reusableApprovalError(approval, err)
	}
	approval.ReservedUses++
	return *approval, metadata, nil
}

func (s *Store) findReusableLocked(req request.ExecRequest) (*ReusableApproval, ReuseMetadata, error) {
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

		metadata := ReuseMetadata{
			ApprovalID:    approval.ID,
			RemainingTTL:  approval.ExpiresAt.Sub(now),
			RemainingUses: remainingUses,
		}

		return approval, metadata, nil
	}

	if expired != nil {
		return expired, ReuseMetadata{}, ErrExpired
	}
	if exhausted != nil {
		return exhausted, ReuseMetadata{}, ErrUseExhausted
	}
	return nil, ReuseMetadata{}, ErrMismatch
}

func (s *Store) FinishReusableAttempt(id string, result DeliveryResult) (ReusableApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	approval, ok := s.approvals[id]
	if !ok {
		return ReusableApproval{}, ErrMismatch
	}
	if !s.now().Before(approval.ExpiresAt) {
		snapshot := *approval
		delete(s.approvals, id)
		return ReusableApproval{}, reusableApprovalError(&snapshot, ErrExpired)
	}
	switch result {
	case DeliveryPayloadDelivered:
		if approval.ReservedUses > 0 {
			approval.ReservedUses--
		}
		approval.Uses++
	case DeliveryPrePayloadFailure:
		if approval.ReservedUses > 0 {
			approval.ReservedUses--
		}
	default:
		return ReusableApproval{}, fmt.Errorf("%w: %q", ErrInvalidDeliveryResult, result)
	}
	if approval.Uses >= approval.MaxUses && approval.ReservedUses == 0 {
		delete(s.approvals, id)
	}

	return *approval, nil
}

func reusableApprovalError(approval *ReusableApproval, err error) error {
	if approval == nil {
		return err
	}
	return &ReusableApprovalError{Approval: *approval, Err: err}
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
		TTL:                    req.TTL,
		ReusableUses:           request.ReusableUsesOrDefault(req.ReusableUses),
		OverrideEnv:            req.OverrideEnv,
		OverriddenAliases:      overridden,
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
		k.TTL == other.TTL &&
		k.ReusableUses == other.ReusableUses &&
		k.OverrideEnv == other.OverrideEnv &&
		slices.Equal(k.OverriddenAliases, other.OverriddenAliases)
}

func (s *Store) randomID(prefix string) (string, error) {
	return randid.Generate(s.random, prefix)
}
