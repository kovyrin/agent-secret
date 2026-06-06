package providerresolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/secretref"
)

type OnePasswordResolver interface {
	Resolve(ctx context.Context, ref string, account string) (string, error)
	DescribeItem(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error)
}

type BitwardenSecretsManagerResolver interface {
	ResolveSecret(ctx context.Context, secret request.Secret) (string, error)
}

type Resolver struct {
	OnePassword             OnePasswordResolver
	BitwardenSecretsManager BitwardenSecretsManagerResolver
}

func New(onePassword OnePasswordResolver, bitwarden BitwardenSecretsManagerResolver) *Resolver {
	return &Resolver{
		OnePassword:             onePassword,
		BitwardenSecretsManager: bitwarden,
	}
}

func (r *Resolver) Resolve(ctx context.Context, secret request.Secret) (string, error) {
	switch secret.Ref.Provider {
	case secretref.ProviderOnePassword:
		if r.OnePassword == nil {
			return "", errors.New("1Password resolver unavailable")
		}
		return r.OnePassword.Resolve(ctx, secret.Ref.Raw, secret.Account)
	case secretref.ProviderBitwardenSecretsManager:
		if r.BitwardenSecretsManager == nil {
			return "", errors.New("bitwarden Secrets Manager resolver unavailable")
		}
		return r.BitwardenSecretsManager.ResolveSecret(ctx, secret)
	default:
		return "", fmt.Errorf("unsupported secret provider %q", secret.Ref.Provider)
	}
}

func (r *Resolver) DescribeItem(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error) {
	if r.OnePassword == nil {
		return itemmetadata.Metadata{}, errors.New("1Password resolver unavailable")
	}
	return r.OnePassword.DescribeItem(ctx, ref, account)
}
