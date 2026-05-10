package opresolver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	onepassword "github.com/kovyrin/onepassword-sdk-go"
)

type fakeSecretsAPI struct {
	value  string
	values map[string]string
	ref    string
	refs   []string
	err    error
	errs   map[string]error
	calls  int
}

func (f *fakeSecretsAPI) Resolve(_ context.Context, ref string) (string, error) {
	f.calls++
	f.ref = ref
	f.refs = append(f.refs, ref)
	if err := f.errs[ref]; err != nil {
		return "", err
	}
	if value, ok := f.values[ref]; ok {
		return value, nil
	}
	if f.err != nil {
		return "", f.err
	}

	return f.value, nil
}

func TestValidateReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{name: "field", ref: "op://Example Vault/Item/password"},
		{name: "section field", ref: "op://Example Vault/Item/API/token"},
		{name: "missing scheme", ref: "Example Vault/Item/password", wantErr: true},
		{name: "blank segment", ref: "op://Example Vault//password", wantErr: true},
		{name: "too short", ref: "op://Example Vault/Item", wantErr: true},
		{name: "too long", ref: "op://Example Vault/Item/Section/Field/extra", wantErr: true},
		{name: "trimmed", ref: " op://Example Vault/Item/password", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateReference(tt.ref)
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected valid reference, got %v", err)
			}
		})
	}
}

func TestResolveSecretReturnsValueWithoutLoggingIt(t *testing.T) {
	t.Parallel()

	const canary = "synthetic-secret-value"
	fake := &fakeSecretsAPI{value: canary}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	secret, err := resolver.ResolveSecret(context.Background(), "op://Example Vault/Item/password")
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}

	if secret.Value() != canary {
		t.Fatal("resolved value did not match fake secret")
	}
	if fake.ref != "op://Example Vault/Item/password" {
		t.Fatalf("resolved unexpected ref: %q", fake.ref)
	}

	metadata := secret.Metadata()
	if metadata.Length != len(canary) {
		t.Fatalf("metadata length = %d, want %d", metadata.Length, len(canary))
	}
	if metadata.SHA256 == "" || metadata.SHA256 == canary {
		t.Fatal("metadata hash was not populated safely")
	}
}

func TestResolveSecretPreservesMultilineTextValue(t *testing.T) {
	t.Parallel()

	const textSecret = "-----BEGIN PRIVATE KEY-----\nline one\nline two\n-----END PRIVATE KEY-----\n"
	fake := &fakeSecretsAPI{value: textSecret}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	secret, err := resolver.ResolveSecret(context.Background(), "op://Example Vault/Document Item/key.pem")
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}

	if secret.Value() != textSecret {
		t.Fatal("resolved multiline value was not preserved exactly")
	}
	if metadata := secret.Metadata(); metadata.Length != len(textSecret) {
		t.Fatalf("metadata length = %d, want %d", metadata.Length, len(textSecret))
	}
}

func TestResolveSecretSerializesSDKCallsPerResolver(t *testing.T) {
	t.Parallel()

	fake := &blockingSecretsAPI{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	resolve := func(ref string) {
		defer wg.Done()
		_, err := resolver.ResolveSecret(context.Background(), ref)
		errs <- err
	}

	wg.Add(1)
	go resolve("op://Example Vault/Item/password")
	<-fake.entered
	released := false
	defer func() {
		if !released {
			close(fake.release)
		}
	}()

	wg.Add(1)
	go resolve("op://Example Vault/Other/password")
	select {
	case <-fake.entered:
		t.Fatal("second resolve entered SDK before first resolve returned")
	case <-time.After(50 * time.Millisecond):
	}

	close(fake.release)
	released = true
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("ResolveSecret returned error: %v", err)
		}
	}
}

func TestResolveSecretWrapsSDKError(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{err: errors.New("locked")}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	_, err = resolver.ResolveSecret(context.Background(), "op://Example Vault/Item/password")
	if err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestItemResolverResolveSecretCanonicalizesPersonalVaultAlias(t *testing.T) {
	t.Parallel()

	const (
		inputRef     = "op://Employee/Fixture Control Plane/CONTROL_PLANE_PERSONAL_API_TOKEN"
		canonicalRef = "op://vault_private/item_control/token_field"
	)
	sectionID := "add more"
	fake := &fakeSecretsAPI{
		values: map[string]string{canonicalRef: "synthetic-control-plane-token"},
		errs: map[string]error{
			inputRef: errors.New("error resolving secret reference: no vault matched the secret reference query"),
		},
	}
	resolver, err := NewResolverWithItemMetadata(
		fake,
		&fakeVaultsAPI{vaults: []onepassword.VaultOverview{
			{ID: "vault_private", Title: "Private", VaultType: onepassword.VaultTypePersonal},
		}},
		&fakeItemsAPI{
			overviews: []onepassword.ItemOverview{
				{ID: "item_control", Title: "Fixture Control Plane", VaultID: "vault_private"},
			},
			item: onepassword.Item{
				ID:       "item_control",
				Title:    "Fixture Control Plane",
				Sections: []onepassword.ItemSection{{ID: sectionID, Title: "add more"}},
				Fields: []onepassword.ItemField{
					{
						ID:        "token_field",
						Title:     "CONTROL_PLANE_PERSONAL_API_TOKEN",
						SectionID: &sectionID,
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     "must-not-be-used",
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	secret, err := resolver.ResolveSecret(context.Background(), inputRef)
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if secret.Value() != "synthetic-control-plane-token" {
		t.Fatal("resolved value did not come from canonical ID ref")
	}
	if fake.calls != 2 {
		t.Fatalf("Resolve calls = %d, want original plus canonical retry", fake.calls)
	}
	if got := fake.refs; len(got) != 2 || got[0] != inputRef || got[1] != canonicalRef {
		t.Fatalf("resolved refs = %v, want [%q %q]", got, inputRef, canonicalRef)
	}
}

func TestItemResolverResolveSecretCanonicalizesSectionQualifiedField(t *testing.T) {
	t.Parallel()

	const (
		inputRef     = "op://Private/Fixture Control Plane/add more/CONTROL_PLANE_PERSONAL_API_TOKEN"
		canonicalRef = "op://vault_private/item_control/token_field"
	)
	sectionID := "section_id"
	fake := &fakeSecretsAPI{
		values: map[string]string{canonicalRef: "synthetic-control-plane-token"},
		errs: map[string]error{
			inputRef: errors.New("error resolving secret reference: no matching sections"),
		},
	}
	resolver, err := NewResolverWithItemMetadata(
		fake,
		&fakeVaultsAPI{vaults: []onepassword.VaultOverview{
			{ID: "vault_private", Title: "Private", VaultType: onepassword.VaultTypePersonal},
		}},
		&fakeItemsAPI{
			overviews: []onepassword.ItemOverview{
				{ID: "item_control", Title: "Fixture Control Plane", VaultID: "vault_private"},
			},
			item: onepassword.Item{
				ID:       "item_control",
				Title:    "Fixture Control Plane",
				Sections: []onepassword.ItemSection{{ID: sectionID, Title: "add more"}},
				Fields: []onepassword.ItemField{
					{
						ID:        "token_field",
						Title:     "CONTROL_PLANE_PERSONAL_API_TOKEN",
						SectionID: &sectionID,
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     "must-not-be-used",
					},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	secret, err := resolver.ResolveSecret(context.Background(), inputRef)
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if secret.Value() != "synthetic-control-plane-token" {
		t.Fatal("resolved value did not come from canonical ID ref")
	}
	if fake.ref != canonicalRef {
		t.Fatalf("last resolved ref = %q, want %q", fake.ref, canonicalRef)
	}
}

func TestItemResolverResolveSecretKeepsNonLookupError(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{err: errors.New("locked")}
	resolver, err := NewResolverWithItemMetadata(
		fake,
		&fakeVaultsAPI{vaults: []onepassword.VaultOverview{
			{ID: "vault_private", Title: "Private", VaultType: onepassword.VaultTypePersonal},
		}},
		&fakeItemsAPI{},
	)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	_, err = resolver.ResolveSecret(context.Background(), "op://Employee/Fixture Control Plane/token")
	if err == nil {
		t.Fatal("expected locked error")
	}
	if fake.calls != 1 {
		t.Fatalf("Resolve calls = %d, want no canonical retry", fake.calls)
	}
}

func TestItemResolverResolveSecretReportsAmbiguousOmittedSection(t *testing.T) {
	t.Parallel()

	const inputRef = "op://Private/Fixture Control Plane/API_TOKEN"
	firstSection := "first"
	secondSection := "second"
	fake := &fakeSecretsAPI{
		errs: map[string]error{
			inputRef: errors.New("error resolving secret reference: no field matched the secret reference query"),
		},
	}
	resolver, err := NewResolverWithItemMetadata(
		fake,
		&fakeVaultsAPI{vaults: []onepassword.VaultOverview{
			{ID: "vault_private", Title: "Private", VaultType: onepassword.VaultTypePersonal},
		}},
		&fakeItemsAPI{
			overviews: []onepassword.ItemOverview{
				{ID: "item_control", Title: "Fixture Control Plane", VaultID: "vault_private"},
			},
			item: onepassword.Item{
				ID:    "item_control",
				Title: "Fixture Control Plane",
				Sections: []onepassword.ItemSection{
					{ID: firstSection, Title: "first"},
					{ID: secondSection, Title: "second"},
				},
				Fields: []onepassword.ItemField{
					{ID: "first_token", Title: "API_TOKEN", SectionID: &firstSection},
					{ID: "second_token", Title: "API_TOKEN", SectionID: &secondSection},
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	_, err = resolver.ResolveSecret(context.Background(), inputRef)
	if !errors.Is(err, ErrAmbiguousField) {
		t.Fatalf("ResolveSecret error = %v, want ErrAmbiguousField", err)
	}
}

type blockingSecretsAPI struct {
	entered chan struct{}
	release chan struct{}
}

func (f *blockingSecretsAPI) Resolve(_ context.Context, _ string) (string, error) {
	f.entered <- struct{}{}
	<-f.release
	return "synthetic-secret-value", nil
}

type fakeVaultsAPI struct {
	vaults []onepassword.VaultOverview
	err    error
}

func (f *fakeVaultsAPI) List(context.Context, ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.vaults, nil
}

type fakeItemsAPI struct {
	overviews []onepassword.ItemOverview
	item      onepassword.Item
	listErr   error
	getErr    error
}

func (f *fakeItemsAPI) List(
	_ context.Context,
	_ string,
	_ ...onepassword.ItemListFilter,
) ([]onepassword.ItemOverview, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.overviews, nil
}

func (f *fakeItemsAPI) Get(context.Context, string, string) (onepassword.Item, error) {
	if f.getErr != nil {
		return onepassword.Item{}, f.getErr
	}
	return f.item, nil
}

func mustItemRef(t *testing.T, raw string) itemmetadata.Ref {
	t.Helper()
	ref, err := itemmetadata.ParseRef(raw)
	if err != nil {
		t.Fatalf("ParseRef returned error: %v", err)
	}
	return ref
}

func TestNewResolverRequiresSecretsAPI(t *testing.T) {
	t.Parallel()

	_, err := NewResolver(nil)
	if err == nil {
		t.Fatal("expected nil secrets API error")
	}
}

func TestNewResolverWithItemMetadataRequiresAPIs(t *testing.T) {
	t.Parallel()

	_, err := NewResolverWithItemMetadata(nil, &fakeVaultsAPI{}, &fakeItemsAPI{})
	if err == nil {
		t.Fatal("expected nil secrets API error")
	}

	_, err = NewResolverWithItemMetadata(&fakeSecretsAPI{}, nil, &fakeItemsAPI{})
	if !errors.Is(err, ErrItemsUnavailable) {
		t.Fatalf("nil vaults error = %v, want ErrItemsUnavailable", err)
	}

	_, err = NewResolverWithItemMetadata(&fakeSecretsAPI{}, &fakeVaultsAPI{}, nil)
	if !errors.Is(err, ErrItemsUnavailable) {
		t.Fatalf("nil items error = %v, want ErrItemsUnavailable", err)
	}
}

func TestNewResolverWithKeepAliveStoresOwner(t *testing.T) {
	t.Parallel()

	owner := &struct{}{}
	resolver, err := newResolverWithKeepAlive(&fakeSecretsAPI{value: "synthetic-secret-value"}, owner)
	if err != nil {
		t.Fatalf("newResolverWithKeepAlive returned error: %v", err)
	}
	if resolver.keepAlive != owner {
		t.Fatal("resolver did not retain keep-alive owner")
	}
}

func TestResolveSecretRejectsInvalidReferenceBeforeSDKCall(t *testing.T) {
	t.Parallel()

	fake := &fakeSecretsAPI{value: "synthetic-secret-value"}
	resolver, err := NewResolver(fake)
	if err != nil {
		t.Fatalf("NewResolver returned error: %v", err)
	}

	_, err = resolver.ResolveSecret(context.Background(), "Example Vault/Item/password")
	if !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("expected invalid reference error, got %v", err)
	}
	if fake.calls != 0 {
		t.Fatalf("invalid reference called SDK %d time(s)", fake.calls)
	}
}

func TestDescribeItemReturnsMetadataWithoutValues(t *testing.T) {
	t.Parallel()

	sectionID := "database"
	vaults := &fakeVaultsAPI{
		vaults: []onepassword.VaultOverview{{ID: "vault_1", Title: "Fixture Infra"}},
	}
	items := &fakeItemsAPI{
		overviews: []onepassword.ItemOverview{
			{ID: "item_1", Title: "Beta PlanetScale Introspection Probe", VaultID: "vault_1"},
		},
		item: onepassword.Item{
			ID:       "item_1",
			Title:    "Beta PlanetScale Introspection Probe",
			Category: onepassword.ItemCategoryDatabase,
			Sections: []onepassword.ItemSection{{ID: sectionID, Title: "connection"}},
			Fields: []onepassword.ItemField{
				{
					ID:        "username",
					Title:     "username",
					FieldType: onepassword.ItemFieldTypeText,
					Value:     "synthetic-user-value",
				},
				{
					ID:        "password",
					Title:     "password",
					SectionID: &sectionID,
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     "synthetic-secret-value",
				},
			},
		},
	}
	resolver, err := NewResolverWithItemMetadata(&fakeSecretsAPI{}, vaults, items)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	metadata, err := resolver.DescribeItem(
		context.Background(),
		mustItemRef(t, "op://Fixture Infra/Beta PlanetScale Introspection Probe"),
		"fixture.1password.com",
	)
	if err != nil {
		t.Fatalf("DescribeItem returned error: %v", err)
	}
	if metadata.Account != "fixture.1password.com" ||
		metadata.Vault != "Fixture Infra" ||
		metadata.Item != "Beta PlanetScale Introspection Probe" ||
		metadata.Category != string(onepassword.ItemCategoryDatabase) {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if len(metadata.Fields) != 2 {
		t.Fatalf("fields = %d, want 2: %+v", len(metadata.Fields), metadata.Fields)
	}
	if metadata.Fields[0].Concealed {
		t.Fatalf("username field should not be concealed: %+v", metadata.Fields[0])
	}
	if !metadata.Fields[1].Concealed {
		t.Fatalf("password field should be concealed: %+v", metadata.Fields[1])
	}
	if metadata.Fields[1].Ref != "op://Fixture Infra/Beta PlanetScale Introspection Probe/connection/password" {
		t.Fatalf("section field ref = %q", metadata.Fields[1].Ref)
	}
	for _, field := range metadata.Fields {
		if field.Ref == "synthetic-secret-value" || field.Ref == "synthetic-user-value" {
			t.Fatalf("field metadata leaked value: %+v", field)
		}
	}
}

func TestDescribeItemAcceptsPersonalVaultAlias(t *testing.T) {
	t.Parallel()

	vaults := &fakeVaultsAPI{
		vaults: []onepassword.VaultOverview{
			{ID: "vault_private", Title: "Private", VaultType: onepassword.VaultTypePersonal},
		},
	}
	items := &fakeItemsAPI{
		overviews: []onepassword.ItemOverview{
			{ID: "item_control", Title: "Fixture Control Plane", VaultID: "vault_private"},
		},
		item: onepassword.Item{
			ID:       "item_control",
			Title:    "Fixture Control Plane",
			Category: onepassword.ItemCategoryLogin,
			Fields: []onepassword.ItemField{
				{
					ID:        "username",
					Title:     "username",
					FieldType: onepassword.ItemFieldTypeText,
					Value:     "synthetic-user-value",
				},
			},
		},
	}
	resolver, err := NewResolverWithItemMetadata(&fakeSecretsAPI{}, vaults, items)
	if err != nil {
		t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
	}

	metadata, err := resolver.DescribeItem(
		context.Background(),
		mustItemRef(t, "op://Employee/Fixture Control Plane"),
		"fixture.1password.com",
	)
	if err != nil {
		t.Fatalf("DescribeItem returned error: %v", err)
	}
	if metadata.Vault != "Private" || metadata.VaultID != "vault_private" {
		t.Fatalf("metadata vault = %q/%q, want Private/vault_private", metadata.Vault, metadata.VaultID)
	}
}

func TestDescribeItemReturnsLookupErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		vaults *fakeVaultsAPI
		items  *fakeItemsAPI
		want   error
	}{
		{
			name:   "vault not found",
			vaults: &fakeVaultsAPI{vaults: []onepassword.VaultOverview{{ID: "vault_1", Title: "Other"}}},
			items:  &fakeItemsAPI{},
			want:   ErrVaultNotFound,
		},
		{
			name: "ambiguous vault",
			vaults: &fakeVaultsAPI{vaults: []onepassword.VaultOverview{
				{ID: "vault_1", Title: "Fixture Infra"},
				{ID: "vault_2", Title: "Fixture Infra"},
			}},
			items: &fakeItemsAPI{},
			want:  ErrAmbiguousVault,
		},
		{
			name:   "item not found",
			vaults: &fakeVaultsAPI{vaults: []onepassword.VaultOverview{{ID: "vault_1", Title: "Fixture Infra"}}},
			items:  &fakeItemsAPI{overviews: []onepassword.ItemOverview{{ID: "item_1", Title: "Other"}}},
			want:   ErrItemNotFound,
		},
		{
			name:   "ambiguous item",
			vaults: &fakeVaultsAPI{vaults: []onepassword.VaultOverview{{ID: "vault_1", Title: "Fixture Infra"}}},
			items: &fakeItemsAPI{overviews: []onepassword.ItemOverview{
				{ID: "item_1", Title: "Beta PlanetScale Introspection Probe"},
				{ID: "item_2", Title: "Beta PlanetScale Introspection Probe"},
			}},
			want: ErrAmbiguousItem,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver, err := NewResolverWithItemMetadata(&fakeSecretsAPI{}, tt.vaults, tt.items)
			if err != nil {
				t.Fatalf("NewResolverWithItemMetadata returned error: %v", err)
			}
			_, err = resolver.DescribeItem(
				context.Background(),
				mustItemRef(t, "op://Fixture Infra/Beta PlanetScale Introspection Probe"),
				"fixture.1password.com",
			)
			if !errors.Is(err, tt.want) {
				t.Fatalf("DescribeItem error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNormalizeDesktopOptionsAllowsDefaultAccount(t *testing.T) {
	t.Parallel()

	opts := normalizeDesktopOptions(ClientOptions{Account: " \t "})
	if opts.Account != "" {
		t.Fatalf("account = %q, want default account sentinel", opts.Account)
	}
}

func TestDesktopAccountUsesExplicitOverride(t *testing.T) {
	account, err := desktopAccountWithDetector(" Fixture ", "FromEnv", func() string { return "Detected" })
	if err != nil {
		t.Fatalf("desktopAccountWithDetector returned error: %v", err)
	}
	if account != "Fixture" {
		t.Fatalf("account = %q, want explicit override", account)
	}
}

func TestDesktopAccountUsesOPAccountEnvironment(t *testing.T) {
	account, err := desktopAccountWithDetector("", " Fixture ", func() string { return "Detected" })
	if err != nil {
		t.Fatalf("desktopAccountWithDetector returned error: %v", err)
	}
	if account != "Fixture" {
		t.Fatalf("account = %q, want OP_ACCOUNT", account)
	}
}

func TestDesktopAccountUsesDetectedDesktopAccountWhenUnset(t *testing.T) {
	account, err := desktopAccountWithDetector("", "", func() string { return " Detected " })
	if err != nil {
		t.Fatalf("desktopAccountWithDetector returned error: %v", err)
	}
	if account != "Detected" {
		t.Fatalf("account = %q, want detected desktop account", account)
	}
}

func TestDesktopAccountRequiresAccountWhenDetectionIsUnavailable(t *testing.T) {
	_, err := desktopAccountWithDetector("", "", func() string { return " \t " })
	if !errors.Is(err, ErrAccountUnknown) {
		t.Fatalf("desktopAccountWithDetector error = %v, want ErrAccountUnknown", err)
	}
}

func TestNormalizeDesktopOptionsTrimsAndDefaults(t *testing.T) {
	t.Parallel()

	opts := normalizeDesktopOptions(ClientOptions{
		Account:            " Fixture ",
		IntegrationName:    " \t ",
		IntegrationVersion: " ",
	})
	if opts.Account != "Fixture" {
		t.Fatalf("account = %q, want Fixture", opts.Account)
	}
	if opts.IntegrationName != "Agent Secret Broker" {
		t.Fatalf("integration name = %q, want default", opts.IntegrationName)
	}
	if opts.IntegrationVersion != "dev" {
		t.Fatalf("integration version = %q, want dev", opts.IntegrationVersion)
	}

	opts = normalizeDesktopOptions(ClientOptions{
		Account:            "Fixture",
		IntegrationName:    "agent-secretd",
		IntegrationVersion: "1.2.3",
	})
	if opts.IntegrationName != "agent-secretd" || opts.IntegrationVersion != "1.2.3" {
		t.Fatalf("explicit integration info was not preserved: %+v", opts)
	}
}
