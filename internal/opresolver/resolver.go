package opresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

var ErrInvalidReference = errors.New("invalid 1Password secret reference")

type SecretsAPI interface {
	Resolve(ctx context.Context, secretReference string) (string, error)
}

type ClientOptions struct {
	Account            string
	IntegrationName    string
	IntegrationVersion string
}

type Resolver struct {
	secrets SecretsAPI
}

type Secret struct {
	value string
}

type SecretMetadata struct {
	Length int
	SHA256 string
}

func NewResolver(secrets SecretsAPI) (*Resolver, error) {
	if secrets == nil {
		return nil, errors.New("secrets API is required")
	}

	return &Resolver{secrets: secrets}, nil
}

func NewDesktopResolver(ctx context.Context, opts ClientOptions) (*Resolver, error) {
	normalized := normalizeDesktopOptions(opts)
	account, err := desktopAccount(ctx, normalized.Account)
	if err != nil {
		return nil, err
	}

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo(normalized.IntegrationName, normalized.IntegrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("create 1Password SDK client: %w", err)
	}

	return NewResolver(client.Secrets())
}

func normalizeDesktopOptions(opts ClientOptions) ClientOptions {
	account := strings.TrimSpace(opts.Account)

	integrationName := strings.TrimSpace(opts.IntegrationName)
	if integrationName == "" {
		integrationName = "Agent Secret Broker"
	}

	integrationVersion := strings.TrimSpace(opts.IntegrationVersion)
	if integrationVersion == "" {
		integrationVersion = "dev"
	}

	return ClientOptions{
		Account:            account,
		IntegrationName:    integrationName,
		IntegrationVersion: integrationVersion,
	}
}

func (r *Resolver) Resolve(ctx context.Context, ref string) (Secret, error) {
	if err := ValidateReference(ref); err != nil {
		return Secret{}, err
	}

	value, err := r.secrets.Resolve(ctx, ref)
	if err != nil {
		return Secret{}, fmt.Errorf("resolve 1Password reference: %w", err)
	}

	return Secret{value: value}, nil
}

func (s Secret) Value() string {
	return s.value
}

func (s Secret) Metadata() SecretMetadata {
	sum := sha256.Sum256([]byte(s.value))
	return SecretMetadata{
		Length: len(s.value),
		SHA256: hex.EncodeToString(sum[:]),
	}
}

func ValidateReference(ref string) error {
	if strings.TrimSpace(ref) != ref || ref == "" {
		return fmt.Errorf("%w: must be non-empty and untrimmed", ErrInvalidReference)
	}

	if !strings.HasPrefix(ref, "op://") {
		return fmt.Errorf("%w: must start with op://", ErrInvalidReference)
	}

	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 3 || len(parts) > 4 {
		return fmt.Errorf("%w: expected op://vault/item[/section]/field-or-text-file", ErrInvalidReference)
	}

	if slices.Contains(parts, "") {
		return fmt.Errorf("%w: path segments must be non-empty", ErrInvalidReference)
	}

	return nil
}
