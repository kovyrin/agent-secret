package opresolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/kovyrin/agent-secret/internal/opaccount"
	"github.com/kovyrin/agent-secret/internal/opref"
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
	mu      sync.Mutex
	// The 1Password SDK releases client IDs from a finalizer on its Client.
	// Keep the owner reachable for as long as this resolver is cached.
	keepAlive any
}

type Secret struct {
	value string
}

type SecretMetadata struct {
	Length int
	SHA256 string
}

func NewResolver(secrets SecretsAPI) (*Resolver, error) {
	return newResolverWithKeepAlive(secrets, nil)
}

func newResolverWithKeepAlive(secrets SecretsAPI, keepAlive any) (*Resolver, error) {
	if secrets == nil {
		return nil, errors.New("secrets API is required")
	}

	return &Resolver{secrets: secrets, keepAlive: keepAlive}, nil
}

func NewDesktopResolver(ctx context.Context, opts ClientOptions) (*Resolver, error) {
	normalized := normalizeDesktopOptions(opts)
	account := desktopAccount(normalized.Account)

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo(normalized.IntegrationName, normalized.IntegrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("create 1Password SDK client: %w", err)
	}

	return newResolverWithKeepAlive(client.Secrets(), client)
}

func desktopAccount(accountOverride string) string {
	return opaccount.SelectDesktopAccount(accountOverride, os.Getenv("OP_ACCOUNT"))
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

func (r *Resolver) ResolveSecret(ctx context.Context, ref string) (Secret, error) {
	if err := ValidateReference(ref); err != nil {
		return Secret{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	value, err := r.secrets.Resolve(ctx, ref)
	runtime.KeepAlive(r.keepAlive)
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
	if _, err := opref.Parse(ref); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}

	return nil
}
