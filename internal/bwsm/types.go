package bwsm

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultKeychainService = "com.kovyrin.agent-secret.bitwarden-secrets-manager"
)

var (
	ErrInvalidTokenAlias = errors.New("invalid Bitwarden Secrets Manager token alias")
	ErrInvalidToken      = errors.New("invalid Bitwarden Secrets Manager token")
	ErrTokenNotFound     = errors.New("bitwarden Secrets Manager token not found")
	ErrKeychainAccess    = errors.New("bitwarden Secrets Manager Keychain access requires repair")
	ErrUnsupportedStore  = errors.New("bitwarden Secrets Manager token store is unsupported on this platform")
	ErrBWSUnavailable    = errors.New("bitwarden Secrets Manager CLI is unavailable")
	ErrInvalidBWSOutput  = errors.New("invalid Bitwarden Secrets Manager CLI output")
)

type Token struct {
	Alias       string    `json:"alias"`
	AccessToken string    `json:"access_token"`
	CreatedAt   time.Time `json:"created_at,omitzero"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
}

type Store interface {
	Get(ctx context.Context, alias string) (Token, bool, error)
	Put(ctx context.Context, token Token) error
	Delete(ctx context.Context, alias string) (bool, error)
	List(ctx context.Context) ([]Token, error)
}
