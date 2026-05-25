package request

import (
	"fmt"
	"strings"
)

type GCPAuthStatusRequest struct {
	GoogleAccount string `json:"google_account,omitempty"`
}

type GCPAuthLoginOptions struct {
	GoogleAccount string
	ExpectedEmail string
}

type GCPAuthLoginRequest struct {
	GoogleAccount string `json:"google_account"`
	ExpectedEmail string `json:"expected_email,omitempty"`
}

type GCPAuthLogoutRequest struct {
	GoogleAccount string `json:"google_account"`
}

func NewGCPAuthStatus(googleAccount string) (GCPAuthStatusRequest, error) {
	account, err := normalizeOptionalGCPAuthAccount(googleAccount)
	if err != nil {
		return GCPAuthStatusRequest{}, err
	}
	return GCPAuthStatusRequest{GoogleAccount: account}, nil
}

func NewGCPAuthLogin(opts GCPAuthLoginOptions) (GCPAuthLoginRequest, error) {
	account, err := normalizeRequiredGCPAuthAccount(opts.GoogleAccount)
	if err != nil {
		return GCPAuthLoginRequest{}, err
	}
	email, err := normalizeOptionalGCPAuthEmail(opts.ExpectedEmail)
	if err != nil {
		return GCPAuthLoginRequest{}, err
	}
	return GCPAuthLoginRequest{GoogleAccount: account, ExpectedEmail: email}, nil
}

func NewGCPAuthLogout(googleAccount string) (GCPAuthLogoutRequest, error) {
	account, err := normalizeRequiredGCPAuthAccount(googleAccount)
	if err != nil {
		return GCPAuthLogoutRequest{}, err
	}
	return GCPAuthLogoutRequest{GoogleAccount: account}, nil
}

func (r GCPAuthStatusRequest) ValidateForDaemon() error {
	account, err := normalizeOptionalGCPAuthAccount(r.GoogleAccount)
	if err != nil {
		return err
	}
	if account != r.GoogleAccount {
		return fmt.Errorf("%w: google_account must be pre-normalized", ErrInvalidGCPAccount)
	}
	return nil
}

func (r GCPAuthLoginRequest) ValidateForDaemon() error {
	expected, err := NewGCPAuthLogin(GCPAuthLoginOptions(r))
	if err != nil {
		return err
	}
	if expected.GoogleAccount != r.GoogleAccount || expected.ExpectedEmail != r.ExpectedEmail {
		return fmt.Errorf("%w: GCP auth login fields must be pre-normalized", ErrInvalidGCPAccount)
	}
	return nil
}

func (r GCPAuthLogoutRequest) ValidateForDaemon() error {
	expected, err := NewGCPAuthLogout(r.GoogleAccount)
	if err != nil {
		return err
	}
	if expected.GoogleAccount != r.GoogleAccount {
		return fmt.Errorf("%w: google_account must be pre-normalized", ErrInvalidGCPAccount)
	}
	return nil
}

func normalizeOptionalGCPAuthAccount(account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", nil
	}
	return validateGCPAuthAccount(account)
}

func normalizeRequiredGCPAuthAccount(account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", fmt.Errorf("%w: google_account is required", ErrInvalidGCPAccount)
	}
	return validateGCPAuthAccount(account)
}

func validateGCPAuthAccount(account string) (string, error) {
	if strings.ContainsAny(account, "\x00\r\n\t") {
		return "", fmt.Errorf("%w: google_account must be a single-line alias", ErrInvalidGCPAccount)
	}
	if len(account) > 128 {
		return "", fmt.Errorf("%w: google_account must be at most 128 characters", ErrInvalidGCPAccount)
	}
	return account, nil
}

func normalizeOptionalGCPAuthEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", nil
	}
	if strings.ContainsAny(email, "\x00\r\n\t ") || !strings.Contains(email, "@") {
		return "", fmt.Errorf("%w: expected_email must be an email address", ErrInvalidGCPAccount)
	}
	return strings.ToLower(email), nil
}
