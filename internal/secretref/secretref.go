package secretref

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/kovyrin/agent-secret/internal/opref"
)

const (
	ProviderOnePassword               = "1password"
	ProviderBitwardenSecretsManager   = "bitwarden-secrets-manager"
	BitwardenSecretsManagerScheme     = "bws://"
	OnePasswordScheme                 = "op://"
	BitwardenSecretsManagerSourceKind = "secrets_manager"
)

var (
	ErrInvalidReference = errors.New("invalid secret reference")

	uuidPattern        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	sourceAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type Reference struct {
	Raw      string
	Provider string
	Vault    string
	Item     string
	Section  string
	Field    string
	Source   string
	SecretID string
}

func Parse(raw string) (Reference, error) {
	switch {
	case strings.HasPrefix(raw, OnePasswordScheme):
		return parseOnePassword(raw)
	case strings.HasPrefix(raw, BitwardenSecretsManagerScheme):
		return ParseBitwardenSecretsManager(raw)
	default:
		return Reference{}, fmt.Errorf("%w: expected op:// or bws:// ref", ErrInvalidReference)
	}
}

func IsSupported(raw string) bool {
	return strings.HasPrefix(raw, OnePasswordScheme) || strings.HasPrefix(raw, BitwardenSecretsManagerScheme)
}

func IsBitwardenSecretsManager(raw string) bool {
	return strings.HasPrefix(raw, BitwardenSecretsManagerScheme)
}

func ValidSourceAlias(alias string) bool {
	return sourceAliasPattern.MatchString(alias)
}

func NormalizeSourceAlias(alias string) (string, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "", fmt.Errorf("%w: source alias is required", ErrInvalidReference)
	}
	if !ValidSourceAlias(alias) {
		return "", fmt.Errorf(
			"%w: source alias %q must match [A-Za-z0-9][A-Za-z0-9._-]*",
			ErrInvalidReference,
			alias,
		)
	}
	return alias, nil
}

func parseOnePassword(raw string) (Reference, error) {
	parsed, err := opref.Parse(raw)
	if err != nil {
		return Reference{}, err
	}
	return Reference{
		Raw:      parsed.Raw,
		Provider: ProviderOnePassword,
		Vault:    parsed.Vault,
		Item:     parsed.Item,
		Section:  parsed.Section,
		Field:    parsed.Field,
	}, nil
}

func ParseBitwardenSecretsManager(raw string) (Reference, error) {
	if strings.TrimSpace(raw) != raw {
		return Reference{}, fmt.Errorf("%w: Bitwarden ref must be trimmed", ErrInvalidReference)
	}
	body := strings.TrimPrefix(raw, BitwardenSecretsManagerScheme)
	if body == "" {
		return Reference{}, fmt.Errorf("%w: Bitwarden secret id is required", ErrInvalidReference)
	}
	if strings.Contains(body, "//") {
		return Reference{}, fmt.Errorf("%w: Bitwarden ref must not contain empty path segments", ErrInvalidReference)
	}
	parts := strings.Split(body, "/")
	switch len(parts) {
	case 1:
		secretID, err := normalizeSecretID(parts[0])
		if err != nil {
			return Reference{}, err
		}
		return Reference{
			Raw:      BitwardenSecretsManagerScheme + secretID,
			Provider: ProviderBitwardenSecretsManager,
			SecretID: secretID,
		}, nil
	case 2:
		source, err := NormalizeSourceAlias(parts[0])
		if err != nil {
			return Reference{}, err
		}
		secretID, err := normalizeSecretID(parts[1])
		if err != nil {
			return Reference{}, err
		}
		return Reference{
			Raw:      BitwardenSecretsManagerScheme + source + "/" + secretID,
			Provider: ProviderBitwardenSecretsManager,
			Source:   source,
			SecretID: secretID,
		}, nil
	default:
		return Reference{}, fmt.Errorf(
			"%w: Bitwarden refs must be bws://<secret-uuid> or bws://<source-alias>/<secret-uuid>",
			ErrInvalidReference,
		)
	}
}

func normalizeSecretID(secretID string) (string, error) {
	secretID = strings.TrimSpace(secretID)
	if secretID == "" {
		return "", fmt.Errorf("%w: Bitwarden secret id is required", ErrInvalidReference)
	}
	if !uuidPattern.MatchString(secretID) {
		return "", fmt.Errorf("%w: Bitwarden secret id must be a UUID", ErrInvalidReference)
	}
	return strings.ToLower(secretID), nil
}
