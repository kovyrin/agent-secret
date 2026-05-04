package opref

import (
	"errors"
	"slices"
	"strings"
)

type Reference struct {
	Raw     string
	Vault   string
	Item    string
	Section string
	Field   string
}

func Parse(ref string) (Reference, error) {
	if strings.TrimSpace(ref) != ref || ref == "" {
		return Reference{}, errors.New("must be non-empty and untrimmed")
	}
	if !strings.HasPrefix(ref, "op://") {
		return Reference{}, errors.New("must start with op://")
	}

	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 3 || len(parts) > 4 {
		return Reference{}, errors.New("expected op://vault/item[/section]/field-or-text-file")
	}
	if slices.Contains(parts, "") {
		return Reference{}, errors.New("path segments must be non-empty")
	}

	parsed := Reference{
		Raw:   ref,
		Vault: parts[0],
		Item:  parts[1],
		Field: parts[len(parts)-1],
	}
	if len(parts) == 4 {
		parsed.Section = parts[2]
	}
	return parsed, nil
}
