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

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/opaccount"
	"github.com/kovyrin/agent-secret/internal/opref"
	onepassword "github.com/kovyrin/onepassword-sdk-go"
)

var (
	ErrInvalidReference = errors.New("invalid 1Password secret reference")
	ErrItemsUnavailable = errors.New("1Password item metadata API is unavailable")
	ErrVaultNotFound    = errors.New("1Password vault not found")
	ErrItemNotFound     = errors.New("1Password item not found")
	ErrAmbiguousVault   = errors.New("1Password vault reference is ambiguous")
	ErrAmbiguousItem    = errors.New("1Password item reference is ambiguous")
)

type SecretsAPI interface {
	Resolve(ctx context.Context, secretReference string) (string, error)
}

type VaultsAPI interface {
	List(ctx context.Context, params ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error)
}

type ItemsAPI interface {
	Get(ctx context.Context, vaultID string, itemID string) (onepassword.Item, error)
	List(ctx context.Context, vaultID string, filters ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error)
}

type ClientOptions struct {
	Account            string
	IntegrationName    string
	IntegrationVersion string
}

type Resolver struct {
	secrets SecretsAPI
	vaults  VaultsAPI
	items   ItemsAPI
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

func NewResolverWithItemMetadata(secrets SecretsAPI, vaults VaultsAPI, items ItemsAPI) (*Resolver, error) {
	if secrets == nil {
		return nil, errors.New("secrets API is required")
	}
	if vaults == nil || items == nil {
		return nil, ErrItemsUnavailable
	}
	return &Resolver{secrets: secrets, vaults: vaults, items: items}, nil
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

	return &Resolver{
		secrets:   client.Secrets(),
		vaults:    client.Vaults(),
		items:     client.Items(),
		keepAlive: client,
	}, nil
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

func (r *Resolver) DescribeItem(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error) {
	if r.vaults == nil || r.items == nil {
		return itemmetadata.Metadata{}, ErrItemsUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	metadata, err := r.describeItemLocked(ctx, ref, account)
	runtime.KeepAlive(r.keepAlive)
	if err != nil {
		return itemmetadata.Metadata{}, err
	}
	return metadata, nil
}

func (r *Resolver) describeItemLocked(ctx context.Context, ref itemmetadata.Ref, account string) (itemmetadata.Metadata, error) {
	vault, err := r.findVault(ctx, ref.Vault)
	if err != nil {
		return itemmetadata.Metadata{}, err
	}
	overview, err := r.findItem(ctx, vault.ID, ref.Item)
	if err != nil {
		return itemmetadata.Metadata{}, err
	}
	item, err := r.items.Get(ctx, vault.ID, overview.ID)
	if err != nil {
		return itemmetadata.Metadata{}, fmt.Errorf("get 1Password item metadata: %w", err)
	}
	return itemMetadataFromSDK(account, vault, item), nil
}

func (r *Resolver) findVault(ctx context.Context, vaultRef string) (onepassword.VaultOverview, error) {
	vaults, err := r.vaults.List(ctx)
	if err != nil {
		return onepassword.VaultOverview{}, fmt.Errorf("list 1Password vaults: %w", err)
	}
	var matches []onepassword.VaultOverview
	for _, vault := range vaults {
		if vault.ID == vaultRef || vault.Title == vaultRef {
			matches = append(matches, vault)
		}
	}
	switch len(matches) {
	case 0:
		return onepassword.VaultOverview{}, fmt.Errorf("%w: %q", ErrVaultNotFound, vaultRef)
	case 1:
		return matches[0], nil
	default:
		return onepassword.VaultOverview{}, fmt.Errorf("%w: %q matched %d vaults", ErrAmbiguousVault, vaultRef, len(matches))
	}
}

func (r *Resolver) findItem(ctx context.Context, vaultID string, itemRef string) (onepassword.ItemOverview, error) {
	items, err := r.items.List(ctx, vaultID)
	if err != nil {
		return onepassword.ItemOverview{}, fmt.Errorf("list 1Password items: %w", err)
	}
	var matches []onepassword.ItemOverview
	for _, item := range items {
		if item.ID == itemRef || item.Title == itemRef {
			matches = append(matches, item)
		}
	}
	switch len(matches) {
	case 0:
		return onepassword.ItemOverview{}, fmt.Errorf("%w: %q", ErrItemNotFound, itemRef)
	case 1:
		return matches[0], nil
	default:
		return onepassword.ItemOverview{}, fmt.Errorf("%w: %q matched %d items", ErrAmbiguousItem, itemRef, len(matches))
	}
}

func itemMetadataFromSDK(
	account string,
	vault onepassword.VaultOverview,
	item onepassword.Item,
) itemmetadata.Metadata {
	sections := make(map[string]string, len(item.Sections))
	for _, section := range item.Sections {
		sections[section.ID] = section.Title
	}
	fields := make([]itemmetadata.Field, 0, len(item.Fields)+len(item.Files))
	for _, field := range item.Fields {
		label := field.Title
		if label == "" {
			label = field.ID
		}
		sectionID, section := fieldSection(field.SectionID, sections)
		ref := itemmetadata.BuildFieldRef(vault.Title, item.Title, section, label)
		fields = append(fields, itemmetadata.Field{
			ID:        field.ID,
			Label:     label,
			Type:      string(field.FieldType),
			SectionID: sectionID,
			Section:   section,
			Concealed: isConcealedFieldType(field.FieldType),
			Ref:       ref,
		})
	}
	for _, file := range item.Files {
		section := sections[file.SectionID]
		ref := itemmetadata.BuildFieldRef(vault.Title, item.Title, section, file.FieldID)
		fields = append(fields, itemmetadata.Field{
			ID:        file.FieldID,
			Label:     file.FieldID,
			Type:      "File",
			SectionID: file.SectionID,
			Section:   section,
			Concealed: true,
			Ref:       ref,
		})
	}
	fields = itemmetadata.UniqueAliases(fields, "")
	return itemmetadata.Metadata{
		Account:  strings.TrimSpace(account),
		VaultID:  vault.ID,
		Vault:    vault.Title,
		ItemID:   item.ID,
		Item:     item.Title,
		Category: string(item.Category),
		Fields:   fields,
	}
}

func fieldSection(sectionID *string, sections map[string]string) (string, string) {
	if sectionID == nil || *sectionID == "" {
		return "", ""
	}
	section := sections[*sectionID]
	if section == "" {
		section = *sectionID
	}
	return *sectionID, section
}

func isConcealedFieldType(fieldType onepassword.ItemFieldType) bool {
	//nolint:exhaustive // Unknown and display-only field types default to non-concealed metadata.
	switch fieldType {
	case onepassword.ItemFieldTypeConcealed,
		onepassword.ItemFieldTypeCreditCardNumber,
		onepassword.ItemFieldTypeTOTP,
		onepassword.ItemFieldTypeSSHKey:
		return true
	default:
		return false
	}
}

func ValidateReference(ref string) error {
	if _, err := opref.Parse(ref); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReference, err)
	}

	return nil
}
