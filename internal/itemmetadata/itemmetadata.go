package itemmetadata

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalidItemRef = errors.New("invalid 1Password item reference")
	ErrInvalidFormat  = errors.New("invalid item describe format")
)

type Format string

const (
	FormatText    Format = "text"
	FormatJSON    Format = "json"
	FormatEnvRefs Format = "env-refs"
)

type Ref struct {
	Raw   string `json:"raw"`
	Vault string `json:"vault"`
	Item  string `json:"item"`
}

type Metadata struct {
	Account  string  `json:"account"`
	VaultID  string  `json:"vault_id,omitempty"`
	Vault    string  `json:"vault"`
	ItemID   string  `json:"item_id,omitempty"`
	Item     string  `json:"item"`
	Category string  `json:"category"`
	Fields   []Field `json:"fields"`
}

type Field struct {
	ID        string `json:"id,omitempty"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	SectionID string `json:"section_id,omitempty"`
	Section   string `json:"section,omitempty"`
	Concealed bool   `json:"concealed"`
	Ref       string `json:"ref"`
	Alias     string `json:"alias"`
}

var envAliasUnsafePattern = regexp.MustCompile(`[^A-Z0-9_]+`)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.TrimSpace(value))
	switch format {
	case "", FormatText:
		return FormatText, nil
	case FormatJSON, FormatEnvRefs:
		return format, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidFormat, value)
	}
}

func ParseRef(raw string) (Ref, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return Ref{}, fmt.Errorf("%w: must be non-empty and untrimmed", ErrInvalidItemRef)
	}
	if !strings.HasPrefix(raw, "op://") {
		return Ref{}, fmt.Errorf("%w: must start with op://", ErrInvalidItemRef)
	}

	parts := strings.Split(strings.TrimPrefix(raw, "op://"), "/")
	validItemRef := len(parts) == 2 || len(parts) == 3 && parts[2] == "*"
	if !validItemRef {
		return Ref{}, fmt.Errorf("%w: expected op://vault/item or op://vault/item/*", ErrInvalidItemRef)
	}
	if slices.Contains(parts[:2], "") {
		return Ref{}, fmt.Errorf("%w: vault and item path segments must be non-empty", ErrInvalidItemRef)
	}
	return Ref{
		Raw:   "op://" + parts[0] + "/" + parts[1],
		Vault: parts[0],
		Item:  parts[1],
	}, nil
}

func EnvAlias(prefix string, label string, fallback string) string {
	prefix = strings.TrimSpace(prefix)
	alias := upperSnake(label)
	if alias == "" {
		alias = upperSnake(fallback)
	}
	if alias == "" {
		alias = "FIELD"
	}
	alias = strings.Trim(prefix, "_") + "_" + alias
	alias = strings.Trim(alias, "_")
	if alias == "" {
		alias = "FIELD"
	}
	if alias[0] >= '0' && alias[0] <= '9' {
		alias = "_" + alias
	}
	return alias
}

func UniqueAliases(fields []Field, prefix string) []Field {
	out := slices.Clone(fields)
	counts := make(map[string]int, len(out))
	for i := range out {
		alias := EnvAlias(prefix, out[i].Label, out[i].ID)
		counts[alias]++
		if counts[alias] > 1 {
			alias = fmt.Sprintf("%s_%d", alias, counts[alias])
		}
		out[i].Alias = alias
	}
	return out
}

func BuildFieldRef(vault string, item string, section string, field string) string {
	ref := "op://" + vault + "/" + item
	if strings.TrimSpace(section) != "" {
		ref += "/" + section
	}
	return ref + "/" + field
}

func upperSnake(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = envAliasUnsafePattern.ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}
