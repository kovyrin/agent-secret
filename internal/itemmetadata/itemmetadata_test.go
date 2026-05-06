package itemmetadata

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseRefAcceptsItemRefsOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want Ref
	}{
		{
			name: "item",
			raw:  "op://Fixture Infra/Beta PlanetScale Introspection Probe",
			want: Ref{
				Raw:   "op://Fixture Infra/Beta PlanetScale Introspection Probe",
				Vault: "Fixture Infra",
				Item:  "Beta PlanetScale Introspection Probe",
			},
		},
		{
			name: "item wildcard",
			raw:  "op://Fixture Infra/Beta PlanetScale Introspection Probe/*",
			want: Ref{
				Raw:   "op://Fixture Infra/Beta PlanetScale Introspection Probe",
				Vault: "Fixture Infra",
				Item:  "Beta PlanetScale Introspection Probe",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseRef(tt.raw)
			if err != nil {
				t.Fatalf("ParseRef returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseRef = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseRefRejectsFieldRefsAndMalformedRefs(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		" op://Fixture Infra/Item",
		"op://Fixture Infra/",
		"op:///Item",
		"op://Fixture Infra/Item/password",
		"op://Fixture Infra/Item/section/password",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			_, err := ParseRef(raw)
			if !errors.Is(err, ErrInvalidItemRef) {
				t.Fatalf("ParseRef error = %v, want ErrInvalidItemRef", err)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    Format
		wantErr error
	}{
		{name: "default", value: "", want: FormatText},
		{name: "text", value: "text", want: FormatText},
		{name: "trimmed json", value: " json ", want: FormatJSON},
		{name: "env refs", value: "env-refs", want: FormatEnvRefs},
		{name: "invalid", value: "yaml", wantErr: ErrInvalidFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseFormat(tt.value)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseFormat error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got != tt.want {
				t.Fatalf("ParseFormat = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUniqueAliasesBuildsStableEnvAliases(t *testing.T) {
	t.Parallel()

	fields := []Field{
		{Label: "service token"},
		{Label: "service-token"},
		{Label: "1st password"},
		{ID: "fallback-id"},
		{},
	}
	got := UniqueAliases(fields, "PLANETSCALE")
	want := []string{
		"PLANETSCALE_SERVICE_TOKEN",
		"PLANETSCALE_SERVICE_TOKEN_2",
		"PLANETSCALE_1ST_PASSWORD",
		"PLANETSCALE_FALLBACK_ID",
		"PLANETSCALE_FIELD",
	}
	for i, field := range got {
		if field.Alias != want[i] {
			t.Fatalf("field %d alias = %q, want %q", i, field.Alias, want[i])
		}
	}
}

func TestEnvAliasHandlesEmptyPrefixAndNumericFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefix   string
		label    string
		fallback string
		want     string
	}{
		{name: "empty prefix", label: "private key", want: "PRIVATE_KEY"},
		{name: "trim prefix underscores", prefix: "__APP__", label: "token", want: "APP_TOKEN"},
		{name: "numeric label", label: "123", want: "_123"},
		{name: "numeric fallback", fallback: "1password", want: "_1PASSWORD"},
		{name: "empty alias", want: "FIELD"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := EnvAlias(tt.prefix, tt.label, tt.fallback); got != tt.want {
				t.Fatalf("EnvAlias = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildFieldRefIncludesOptionalSection(t *testing.T) {
	t.Parallel()

	if got := BuildFieldRef("Demo Infra", "Deploy Token", "", "credential"); got != "op://Demo Infra/Deploy Token/credential" {
		t.Fatalf("BuildFieldRef without section = %q", got)
	}
	if got := BuildFieldRef("Demo Infra", "Deploy Token", "api", "credential"); got != "op://Demo Infra/Deploy Token/api/credential" {
		t.Fatalf("BuildFieldRef with section = %q", got)
	}
	if got := BuildFieldRef("Demo Infra", "Deploy Token", " \t ", "credential"); got != "op://Demo Infra/Deploy Token/credential" {
		t.Fatalf("BuildFieldRef blank section = %q", got)
	}
}
