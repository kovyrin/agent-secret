package broker

import (
	"slices"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/request"
)

type secretIdentity struct {
	ref       request.SecretRef
	account   string
	source    string
	bitwarden request.BitwardenSource
}

func uniqueSecretIdentities(secrets []request.Secret) []secretIdentity {
	seen := make(map[secretIdentity]struct{}, len(secrets))
	identities := make([]secretIdentity, 0, len(secrets))
	for _, secret := range secrets {
		identity := identityForSecret(secret)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, func(a secretIdentity, b secretIdentity) int {
		if a.ref.Raw < b.ref.Raw {
			return -1
		}
		if a.ref.Raw > b.ref.Raw {
			return 1
		}
		if a.account < b.account {
			return -1
		}
		if a.account > b.account {
			return 1
		}
		if a.source < b.source {
			return -1
		}
		if a.source > b.source {
			return 1
		}
		if a.bitwarden.TokenAlias < b.bitwarden.TokenAlias {
			return -1
		}
		if a.bitwarden.TokenAlias > b.bitwarden.TokenAlias {
			return 1
		}
		if a.bitwarden.APIURL < b.bitwarden.APIURL {
			return -1
		}
		if a.bitwarden.APIURL > b.bitwarden.APIURL {
			return 1
		}
		if a.bitwarden.IdentityURL < b.bitwarden.IdentityURL {
			return -1
		}
		if a.bitwarden.IdentityURL > b.bitwarden.IdentityURL {
			return 1
		}
		return 0
	})
	return identities
}

func pendingIdentities(ordered []secretIdentity, pending map[secretIdentity]struct{}) []secretIdentity {
	identities := make([]secretIdentity, 0, len(pending))
	for _, identity := range ordered {
		if _, ok := pending[identity]; ok {
			identities = append(identities, identity)
		}
	}
	return identities
}

func fanoutValues(secrets []request.Secret, refValues map[secretIdentity]string) map[string]string {
	values := make(map[string]string, len(secrets))
	for _, secret := range secrets {
		values[secret.Alias] = refValues[identityForSecret(secret)]
	}
	return values
}

func auditRefsForIdentity(secrets []request.Secret, identity secretIdentity) []audit.SecretRef {
	refs := []audit.SecretRef{}
	for _, secret := range secrets {
		if identityForSecret(secret) != identity {
			continue
		}
		refs = append(refs, audit.SecretRef{
			Alias:               secret.Alias,
			Ref:                 secret.Ref.Raw,
			Account:             secret.Account,
			Source:              secret.Source,
			BitwardenTokenAlias: secret.Bitwarden.TokenAlias,
		})
	}
	if len(refs) == 0 {
		return []audit.SecretRef{{
			Ref:                 identity.ref.Raw,
			Account:             identity.account,
			Source:              identity.source,
			BitwardenTokenAlias: identity.bitwarden.TokenAlias,
		}}
	}
	return refs
}

func auditRefsForIdentities(secrets []request.Secret, identities []secretIdentity) []audit.SecretRef {
	refs := []audit.SecretRef{}
	seen := make(map[secretIdentity]struct{}, len(identities))
	for _, identity := range identities {
		seen[identity] = struct{}{}
	}
	matched := make(map[secretIdentity]struct{}, len(identities))
	for _, secret := range secrets {
		identity := identityForSecret(secret)
		if _, ok := seen[identity]; !ok {
			continue
		}
		matched[identity] = struct{}{}
		refs = append(refs, audit.SecretRef{
			Alias:               secret.Alias,
			Ref:                 secret.Ref.Raw,
			Account:             secret.Account,
			Source:              secret.Source,
			BitwardenTokenAlias: secret.Bitwarden.TokenAlias,
		})
	}
	for _, identity := range identities {
		if _, ok := matched[identity]; ok {
			continue
		}
		refs = append(refs, audit.SecretRef{
			Ref:                 identity.ref.Raw,
			Account:             identity.account,
			Source:              identity.source,
			BitwardenTokenAlias: identity.bitwarden.TokenAlias,
		})
	}
	return refs
}

func identityForSecret(secret request.Secret) secretIdentity {
	return secretIdentity{
		ref:       secret.Ref,
		account:   secret.Account,
		source:    secret.Source,
		bitwarden: secret.Bitwarden,
	}
}

func (i secretIdentity) secret() request.Secret {
	return request.Secret{
		Ref:       i.ref,
		Account:   i.account,
		Source:    i.source,
		Bitwarden: i.bitwarden,
	}
}
