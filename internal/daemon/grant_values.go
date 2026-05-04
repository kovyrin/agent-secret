package daemon

import (
	"slices"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/request"
)

type secretIdentity struct {
	ref     string
	account string
}

func uniqueSecretIdentities(secrets []request.Secret) []secretIdentity {
	seen := make(map[secretIdentity]struct{}, len(secrets))
	identities := make([]secretIdentity, 0, len(secrets))
	for _, secret := range secrets {
		identity := secretIdentity{ref: secret.Ref.Raw, account: secret.Account}
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	slices.SortFunc(identities, func(a secretIdentity, b secretIdentity) int {
		if a.ref < b.ref {
			return -1
		}
		if a.ref > b.ref {
			return 1
		}
		if a.account < b.account {
			return -1
		}
		if a.account > b.account {
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
		values[secret.Alias] = refValues[secretIdentity{ref: secret.Ref.Raw, account: secret.Account}]
	}
	return values
}

func aliases(secrets []request.Secret) []string {
	aliases := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		aliases = append(aliases, secret.Alias)
	}
	slices.Sort(aliases)
	return aliases
}

func auditRefsForIdentity(secrets []request.Secret, identity secretIdentity) []audit.SecretRef {
	refs := []audit.SecretRef{}
	for _, secret := range secrets {
		if secret.Ref.Raw != identity.ref || secret.Account != identity.account {
			continue
		}
		refs = append(refs, audit.SecretRef{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	if len(refs) == 0 {
		return []audit.SecretRef{{Ref: identity.ref, Account: identity.account}}
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
		identity := secretIdentity{ref: secret.Ref.Raw, account: secret.Account}
		if _, ok := seen[identity]; !ok {
			continue
		}
		matched[identity] = struct{}{}
		refs = append(refs, audit.SecretRef{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	for _, identity := range identities {
		if _, ok := matched[identity]; ok {
			continue
		}
		refs = append(refs, audit.SecretRef{Ref: identity.ref, Account: identity.account})
	}
	return refs
}
