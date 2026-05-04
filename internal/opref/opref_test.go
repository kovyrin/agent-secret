package opref

import "testing"

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		want    Reference
		wantErr bool
	}{
		{
			name: "field",
			ref:  "op://Example Vault/Item/password",
			want: Reference{
				Raw:   "op://Example Vault/Item/password",
				Vault: "Example Vault",
				Item:  "Item",
				Field: "password",
			},
		},
		{
			name: "section field",
			ref:  "op://Example Vault/Item/API/token",
			want: Reference{
				Raw:     "op://Example Vault/Item/API/token",
				Vault:   "Example Vault",
				Item:    "Item",
				Section: "API",
				Field:   "token",
			},
		},
		{name: "blank segment", ref: "op://Example Vault//password", wantErr: true},
		{name: "too short", ref: "op://Example Vault/Item", wantErr: true},
		{name: "too long", ref: "op://Example Vault/Item/Section/Field/extra", wantErr: true},
		{name: "trimmed", ref: " op://Example Vault/Item/password", wantErr: true},
		{name: "wrong scheme", ref: "vault/item/password", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Parse returned nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Parse = %+v, want %+v", got, tt.want)
			}
		})
	}
}
