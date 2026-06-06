package bwsm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/secretref"
)

const keychainIndexAccount = "__agent_secret_bitwarden_secrets_manager_tokens__"

type KeychainStore struct {
	service string
	backend keychainBackend
	now     func() time.Time
}

type keychainBackend struct {
	get    func(context.Context, string, string) ([]byte, error)
	put    func(context.Context, string, string, []byte) error
	delete func(context.Context, string, string) (bool, error)
}

type keychainIndex struct {
	Aliases []string `json:"aliases"`
}

func NewKeychainStore(service string) *KeychainStore {
	service = strings.TrimSpace(service)
	if service == "" {
		service = DefaultKeychainService
	}
	return &KeychainStore{
		service: service,
		backend: keychainBackend{
			get:    keychainGet,
			put:    keychainPut,
			delete: keychainDelete,
		},
		now: time.Now,
	}
}

func (s *KeychainStore) Get(ctx context.Context, alias string) (Token, bool, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, false, err
	}
	alias, err := normalizeTokenAlias(alias)
	if err != nil {
		return Token{}, false, err
	}
	raw, err := s.backend.get(ctx, s.service, alias)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return Token{}, false, nil
		}
		return Token{}, false, err
	}
	var token Token
	if err := json.Unmarshal(raw, &token); err != nil {
		return Token{}, false, fmt.Errorf("decode Bitwarden Secrets Manager token metadata: %w", err)
	}
	token.Alias = alias
	if token.AccessToken == "" {
		return Token{}, false, fmt.Errorf("%w: stored token is empty", ErrInvalidToken)
	}
	return token, true, nil
}

func (s *KeychainStore) Put(ctx context.Context, token Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	alias, err := normalizeTokenAlias(token.Alias)
	if err != nil {
		return err
	}
	accessToken := strings.TrimSpace(token.AccessToken)
	if accessToken == "" {
		return fmt.Errorf("%w: access token is required", ErrInvalidToken)
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	stored, found, err := s.Get(ctx, alias)
	if err != nil {
		if !errors.Is(err, ErrKeychainAccess) {
			return err
		}
		found = false
	}
	if token.CreatedAt.IsZero() {
		if found && !stored.CreatedAt.IsZero() {
			token.CreatedAt = stored.CreatedAt
		} else {
			token.CreatedAt = now().UTC()
		}
	}
	token.Alias = alias
	token.AccessToken = accessToken
	token.UpdatedAt = now().UTC()
	raw, err := json.Marshal(token) //nolint:gosec // G117: token JSON is written only to the user's Keychain item.
	if err != nil {
		return fmt.Errorf("encode Bitwarden Secrets Manager token metadata: %w", err)
	}
	if err := s.backend.put(ctx, s.service, alias, raw); err != nil {
		return err
	}
	index, err := s.loadRepairableIndex(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(index.Aliases, alias) {
		index.Aliases = append(index.Aliases, alias)
		slices.Sort(index.Aliases)
	}
	return s.saveIndex(ctx, index)
}

func (s *KeychainStore) Delete(ctx context.Context, alias string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	alias, err := normalizeTokenAlias(alias)
	if err != nil {
		return false, err
	}
	deleted, err := s.backend.delete(ctx, s.service, alias)
	if err != nil {
		return false, err
	}
	index, err := s.loadRepairableIndex(ctx)
	if err != nil {
		return false, err
	}
	index.Aliases = slices.DeleteFunc(index.Aliases, func(candidate string) bool {
		return candidate == alias
	})
	if err := s.saveIndex(ctx, index); err != nil {
		return false, err
	}
	return deleted, nil
}

func (s *KeychainStore) List(ctx context.Context) ([]Token, error) {
	index, err := s.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	tokens := make([]Token, 0, len(index.Aliases))
	for _, alias := range index.Aliases {
		token, found, err := s.Get(ctx, alias)
		if err != nil {
			return nil, err
		}
		if found {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func ListAliases(ctx context.Context, store Store) ([]string, error) {
	tokens, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	aliases := make([]string, 0, len(tokens))
	for _, token := range tokens {
		aliases = append(aliases, token.Alias)
	}
	slices.Sort(aliases)
	return aliases, nil
}

func (s *KeychainStore) loadIndex(ctx context.Context) (keychainIndex, error) {
	raw, err := s.backend.get(ctx, s.service, keychainIndexAccount)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return keychainIndex{}, nil
		}
		return keychainIndex{}, err
	}
	var index keychainIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return keychainIndex{}, fmt.Errorf("decode Bitwarden Secrets Manager token index: %w", err)
	}
	return index, nil
}

func (s *KeychainStore) loadRepairableIndex(ctx context.Context) (keychainIndex, error) {
	index, err := s.loadIndex(ctx)
	if err == nil {
		return index, nil
	}
	if !errors.Is(err, ErrKeychainAccess) {
		return keychainIndex{}, err
	}
	if _, deleteErr := s.backend.delete(ctx, s.service, keychainIndexAccount); deleteErr != nil && !errors.Is(deleteErr, ErrTokenNotFound) {
		return keychainIndex{}, deleteErr
	}
	return keychainIndex{}, nil
}

func (s *KeychainStore) saveIndex(ctx context.Context, index keychainIndex) error {
	raw, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode Bitwarden Secrets Manager token index: %w", err)
	}
	return s.backend.put(ctx, s.service, keychainIndexAccount, raw)
}

func normalizeTokenAlias(alias string) (string, error) {
	normalized, err := secretref.NormalizeSourceAlias(alias)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidTokenAlias, err)
	}
	return normalized, nil
}
