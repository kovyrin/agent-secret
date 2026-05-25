package gcpauth

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultAuthEndpoint     = "https://accounts.google.com/o/oauth2/v2/auth"
	DefaultTokenEndpoint    = "https://oauth2.googleapis.com/token" //nolint:gosec // OAuth token endpoint URL, not credential material.
	DefaultUserInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo"
	DefaultIAMEndpoint      = "https://iamcredentials.googleapis.com"
	DefaultKeychainService  = "com.kovyrin.agent-secret.gcp.oauth"
)

var (
	ErrCredentialNotFound = errors.New("GCP bootstrap credential not found")
	ErrInvalidCredential  = errors.New("invalid GCP bootstrap credential")
	ErrOAuthClientID      = errors.New("GCP OAuth client id is required")
	ErrOAuthState         = errors.New("GCP OAuth callback state mismatch")
	ErrOAuthNoRefresh     = errors.New("GCP OAuth response did not include a refresh token")
	ErrOAuthEmailMismatch = errors.New("GCP OAuth email did not match expected email")
	ErrKeychainAccess     = errors.New("GCP Keychain access requires repair")
	ErrUnsupportedStore   = errors.New("GCP auth store is unsupported on this platform")
)

type Credential struct {
	GoogleAccount string    `json:"google_account"`
	Email         string    `json:"email,omitempty"`
	RefreshToken  string    `json:"refresh_token"`
	Scopes        []string  `json:"scopes,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitzero"`
	UpdatedAt     time.Time `json:"updated_at,omitzero"`
}

type Store interface {
	Get(ctx context.Context, googleAccount string) (Credential, bool, error)
	Put(ctx context.Context, credential Credential) error
	Delete(ctx context.Context, googleAccount string) (bool, error)
	List(ctx context.Context) ([]Credential, error)
}

func defaultOAuthScopes() []string {
	return []string{
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/cloud-platform",
	}
}
