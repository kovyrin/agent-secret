package broker

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/randid"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrSessionNotFound      = errors.New("session not found")
	ErrSessionReadExhausted = errors.New("session read count exhausted")
	ErrSessionPeerMismatch  = errors.New("session peer mismatch")
)

type sessionStore struct {
	mu            sync.Mutex
	now           func() time.Time
	random        io.Reader
	authorizer    SessionPeerAuthorizer
	sessions      map[string]*sessionRecord
	sessionTokens map[string]*sessionRecord
}

type sessionRecord struct {
	ID            string
	Token         string
	Reason        string
	CWD           string
	Secrets       []request.Secret
	Env           map[string]string
	SecretAliases []string
	ExpiresAt     time.Time
	MaxReads      int
	PeerBinding   SessionPeerBinding
	Reads         int
	ReservedReads int
	OverrideEnv   bool
}

type sessionReservation struct {
	SessionID      string
	SessionToken   string
	Reason         string
	CWD            string
	Secrets        []request.Secret
	Env            map[string]string
	SecretAliases  []string
	ExpiresAt      time.Time
	MaxReads       int
	RemainingReads int
	OverrideEnv    bool
}

func newSessionStore(now func() time.Time, authorizer SessionPeerAuthorizer) *sessionStore {
	if now == nil {
		now = time.Now
	}
	if authorizer == nil {
		defaultAuthorizer := newProcessTreeSessionPeerAuthorizer()
		authorizer = defaultAuthorizer
	}
	return &sessionStore{
		now:           now,
		random:        rand.Reader,
		authorizer:    authorizer,
		sessions:      make(map[string]*sessionRecord),
		sessionTokens: make(map[string]*sessionRecord),
	}
}

func (s *sessionStore) create(
	req request.SessionCreateRequest,
	env map[string]string,
	peerBinding SessionPeerBinding,
) (request.SessionSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.randomID()
	if err != nil {
		return request.SessionSummary{}, err
	}
	token, err := s.randomToken()
	if err != nil {
		return request.SessionSummary{}, err
	}
	record := &sessionRecord{
		ID:            id,
		Token:         token,
		Reason:        req.Reason,
		CWD:           req.CWD,
		Secrets:       slices.Clone(req.Secrets),
		Env:           cloneEnv(env),
		SecretAliases: request.SecretAliases(req.Secrets),
		ExpiresAt:     req.ExpiresAt,
		MaxReads:      req.MaxReads,
		PeerBinding:   peerBinding,
		OverrideEnv:   req.OverrideEnv,
	}
	s.sessions[id] = record
	s.sessionTokens[token] = record
	return record.summary(), nil
}

func (s *sessionStore) reserve(req request.SessionResolveRequest, peer peercred.Info) (sessionReservation, error) {
	if err := peercred.Validate(peer, req.ExpectedPeer); err != nil {
		return sessionReservation{}, fmt.Errorf("%w: %w", ErrSessionPeerMismatch, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.sessionTokens[req.SessionToken]
	if !ok {
		return sessionReservation{}, ErrSessionNotFound
	}
	if !s.now().Before(record.ExpiresAt) {
		s.deleteRecord(record)
		return sessionReservation{}, approval.ErrRequestExpired
	}
	if record.CWD != req.CWD {
		return sessionReservation{}, fmt.Errorf("%w: cwd %q != %q", ErrSessionPeerMismatch, req.CWD, record.CWD)
	}
	if err := s.authorizer.ValidateSessionPeer(record.PeerBinding, peer); err != nil {
		return sessionReservation{}, err
	}
	if record.Reads+record.ReservedReads >= record.MaxReads {
		s.deleteRecord(record)
		return sessionReservation{}, ErrSessionReadExhausted
	}

	secrets, env, aliases, err := selectSessionAliases(record, req.RequestedAliases)
	if err != nil {
		return sessionReservation{}, err
	}
	record.ReservedReads++
	return sessionReservation{
		SessionID:      record.ID,
		SessionToken:   record.Token,
		Reason:         record.Reason,
		CWD:            record.CWD,
		Secrets:        secrets,
		Env:            env,
		SecretAliases:  aliases,
		ExpiresAt:      record.ExpiresAt,
		MaxReads:       record.MaxReads,
		RemainingReads: record.remainingReads(),
		OverrideEnv:    record.OverrideEnv,
	}, nil
}

func (s *sessionStore) finishReservation(sessionToken string, delivered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.sessionTokens[sessionToken]
	if !ok || record.ReservedReads <= 0 {
		return
	}
	record.ReservedReads--
	if delivered {
		record.Reads++
	}
	if record.Reads >= record.MaxReads || !s.now().Before(record.ExpiresAt) {
		s.deleteRecord(record)
	}
}

func (s *sessionStore) destroy(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sessionID]; !ok {
		return false
	}
	s.deleteRecord(s.sessions[sessionID])
	return true
}

func (s *sessionStore) destroyAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(s.sessions)
	s.sessions = make(map[string]*sessionRecord)
	s.sessionTokens = make(map[string]*sessionRecord)
	return count
}

func (s *sessionStore) list() []request.SessionSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	summaries := make([]request.SessionSummary, 0, len(s.sessions))
	for _, record := range s.sessions {
		if !now.Before(record.ExpiresAt) || record.Reads+record.ReservedReads >= record.MaxReads {
			s.deleteRecord(record)
			continue
		}
		summaries = append(summaries, record.summary())
	}
	slices.SortFunc(summaries, func(a request.SessionSummary, b request.SessionSummary) int {
		if a.ExpiresAt.Before(b.ExpiresAt) {
			return -1
		}
		if b.ExpiresAt.Before(a.ExpiresAt) {
			return 1
		}
		return stringsCompare(a.SessionID, b.SessionID)
	})
	return summaries
}

func (s *sessionStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*sessionRecord)
	s.sessionTokens = make(map[string]*sessionRecord)
}

func (s *sessionStore) randomID() (string, error) {
	return randid.Generate(s.random, "asid")
}

func (s *sessionStore) randomToken() (string, error) {
	return randid.Generate(s.random, "astok")
}

func (s *sessionStore) deleteRecord(record *sessionRecord) {
	delete(s.sessions, record.ID)
	delete(s.sessionTokens, record.Token)
}

func (s sessionRecord) summary() request.SessionSummary {
	return request.SessionSummary{
		SessionID:      s.ID,
		SessionToken:   s.Token,
		Reason:         s.Reason,
		CWD:            s.CWD,
		SecretAliases:  slices.Clone(s.SecretAliases),
		ExpiresAt:      s.ExpiresAt,
		MaxReads:       s.MaxReads,
		RemainingReads: s.remainingReads(),
		OverrideEnv:    s.OverrideEnv,
	}
}

func (s sessionRecord) remainingReads() int {
	remaining := s.MaxReads - s.Reads - s.ReservedReads
	if remaining < 0 {
		return 0
	}
	return remaining
}

func selectSessionAliases(record *sessionRecord, requested []string) ([]request.Secret, map[string]string, []string, error) {
	aliases, err := request.NormalizeAliases(requested)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(aliases) == 0 {
		aliases = slices.Clone(record.SecretAliases)
	}
	slices.Sort(aliases)

	secretByAlias := make(map[string]request.Secret, len(record.Secrets))
	for _, secret := range record.Secrets {
		secretByAlias[secret.Alias] = secret
	}
	secrets := make([]request.Secret, 0, len(aliases))
	env := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		secret, ok := secretByAlias[alias]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: session has no approved alias %q", request.ErrInvalidAlias, alias)
		}
		value, ok := record.Env[alias]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: session value missing for alias %q", request.ErrInvalidAlias, alias)
		}
		secrets = append(secrets, secret)
		env[alias] = value
	}
	return secrets, env, aliases, nil
}

func cloneEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	maps.Copy(out, env)
	return out
}

func stringsCompare(a string, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
