package gcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const keychainIndexAccount = "__agent_secret_gcp_accounts__"

type KeychainStore struct {
	service string
}

type keychainIndex struct {
	Accounts []string `json:"accounts"`
}

func NewKeychainStore(service string) *KeychainStore {
	service = strings.TrimSpace(service)
	if service == "" {
		service = DefaultKeychainService
	}
	return &KeychainStore{service: service}
}

func (s *KeychainStore) Get(ctx context.Context, googleAccount string) (Credential, bool, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, false, err
	}
	raw, err := keychainGet(ctx, s.service, googleAccount)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return Credential{}, false, nil
		}
		return Credential{}, false, err
	}
	var credential Credential
	if err := json.Unmarshal(raw, &credential); err != nil {
		return Credential{}, false, fmt.Errorf("decode GCP Keychain credential metadata: %w", err)
	}
	if credential.GoogleAccount == "" {
		credential.GoogleAccount = googleAccount
	}
	return credential, true, nil
}

func (s *KeychainStore) Put(ctx context.Context, credential Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(credential.GoogleAccount) == "" {
		return fmt.Errorf("%w: google_account is required", ErrInvalidCredential)
	}
	raw, err := json.Marshal(credential) //nolint:gosec // G117: credential JSON is written only to the user's Keychain item.
	if err != nil {
		return fmt.Errorf("encode GCP Keychain credential metadata: %w", err)
	}
	if err := keychainPut(ctx, s.service, credential.GoogleAccount, raw); err != nil {
		return err
	}
	index, err := s.loadIndex(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(index.Accounts, credential.GoogleAccount) {
		index.Accounts = append(index.Accounts, credential.GoogleAccount)
		slices.Sort(index.Accounts)
	}
	return s.saveIndex(ctx, index)
}

func (s *KeychainStore) Delete(ctx context.Context, googleAccount string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	deleted, err := keychainDelete(ctx, s.service, googleAccount)
	if err != nil {
		return false, err
	}
	index, err := s.loadIndex(ctx)
	if err != nil {
		return false, err
	}
	index.Accounts = slices.DeleteFunc(index.Accounts, func(account string) bool {
		return account == googleAccount
	})
	if err := s.saveIndex(ctx, index); err != nil {
		return false, err
	}
	return deleted, nil
}

func (s *KeychainStore) List(ctx context.Context) ([]Credential, error) {
	index, err := s.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	credentials := make([]Credential, 0, len(index.Accounts))
	for _, account := range index.Accounts {
		credential, found, err := s.Get(ctx, account)
		if err != nil {
			return nil, err
		}
		if found {
			credentials = append(credentials, credential)
		}
	}
	return credentials, nil
}

func (s *KeychainStore) loadIndex(ctx context.Context) (keychainIndex, error) {
	raw, err := keychainGet(ctx, s.service, keychainIndexAccount)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return keychainIndex{}, nil
		}
		return keychainIndex{}, err
	}
	var index keychainIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		return keychainIndex{}, fmt.Errorf("decode GCP Keychain credential index: %w", err)
	}
	return index, nil
}

func (s *KeychainStore) saveIndex(ctx context.Context, index keychainIndex) error {
	raw, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("encode GCP Keychain credential index: %w", err)
	}
	return keychainPut(ctx, s.service, keychainIndexAccount, raw)
}
