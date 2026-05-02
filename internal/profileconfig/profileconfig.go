package profileconfig

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
	"gopkg.in/yaml.v3"
)

const currentVersion = 1

var (
	ErrConfigNotFound  = errors.New("profile config not found")
	ErrInvalidConfig   = errors.New("invalid profile config")
	ErrProfileNotFound = errors.New("profile not found")
)

type LoadOptions struct {
	Name       string
	ConfigPath string
	StartDir   string
}

type Profile struct {
	Name       string
	SourcePath string
	Account    string
	Reason     string
	Secrets    []request.SecretSpec
	TTL        time.Duration
}

type configFile struct {
	Version        int                    `yaml:"version"`
	Account        string                 `yaml:"account"`
	DefaultProfile string                 `yaml:"default_profile"`
	Profiles       map[string]profileYAML `yaml:"profiles"`
}

type profileYAML struct {
	Account string                `yaml:"account"`
	Include []string              `yaml:"include"`
	Reason  string                `yaml:"reason"`
	Secrets map[string]secretYAML `yaml:"secrets"`
	TTL     string                `yaml:"ttl"`
}

type resolvedProfile struct {
	account string
	reason  string
	secrets map[string]resolvedSecret
	ttl     time.Duration
}

type resolvedSecret struct {
	account string
	ref     string
}

type secretYAML struct {
	Ref     string
	Account string
}

func (s *secretYAML) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var ref string
		if err := value.Decode(&ref); err != nil {
			return err
		}
		s.Ref = ref
		return nil
	case yaml.MappingNode:
		return s.unmarshalMapping(value)
	case yaml.DocumentNode, yaml.SequenceNode, yaml.AliasNode:
		return errors.New("secret must be a ref string or mapping")
	}
	return errors.New("secret must be a ref string or mapping")
}

func (s *secretYAML) unmarshalMapping(value *yaml.Node) error {
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		item := value.Content[i+1]
		switch key {
		case "ref":
			if err := item.Decode(&s.Ref); err != nil {
				return err
			}
		case "account":
			if err := item.Decode(&s.Account); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown secret field %q", key)
		}
	}
	return nil
}

func Load(opts LoadOptions) (Profile, error) {
	path, err := Find(opts.ConfigPath, opts.StartDir)
	if err != nil {
		return Profile{}, err
	}

	//nolint:gosec // G304: config path is selected from explicit project config discovery and parsed as configuration only.
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile config %s: %w", path, err)
	}

	var doc configFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return Profile{}, fmt.Errorf("%w: parse %s: %w", ErrInvalidConfig, path, err)
	}
	if doc.Version != currentVersion {
		return Profile{}, fmt.Errorf("%w: %s version must be %d", ErrInvalidConfig, path, currentVersion)
	}
	if len(doc.Profiles) == 0 {
		return Profile{}, fmt.Errorf("%w: %s must define at least one profile", ErrInvalidConfig, path)
	}

	profileName := opts.Name
	if profileName == "" {
		profileName = doc.DefaultProfile
	}
	if profileName == "" {
		return Profile{}, fmt.Errorf("%w: %s default_profile is required when no profile name is provided", ErrProfileNotFound, path)
	}

	resolved, err := resolveProfile(doc, path, profileName, nil)
	if err != nil {
		return Profile{}, err
	}
	secrets, err := sortedSecrets(resolved.secrets, path, profileName)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		Name:       profileName,
		SourcePath: path,
		Account:    resolved.account,
		Reason:     resolved.reason,
		Secrets:    secrets,
		TTL:        resolved.ttl,
	}, nil
}

func resolveProfile(doc configFile, path string, profileName string, stack []string) (resolvedProfile, error) {
	rawProfile, ok := doc.Profiles[profileName]
	if !ok {
		return resolvedProfile{}, fmt.Errorf("%w: %q in %s", ErrProfileNotFound, profileName, path)
	}
	if slices.Contains(stack, profileName) {
		cycle := append(slices.Clone(stack), profileName)
		return resolvedProfile{}, fmt.Errorf("%w: %s profile include cycle: %s", ErrInvalidConfig, path, strings.Join(cycle, " -> "))
	}

	result := resolvedProfile{
		account: effectiveAccount(doc.Account, rawProfile.Account),
		secrets: make(map[string]resolvedSecret),
	}
	nextStack := append(slices.Clone(stack), profileName)
	for _, includeName := range rawProfile.Include {
		includeName = strings.TrimSpace(includeName)
		if includeName == "" {
			return resolvedProfile{}, fmt.Errorf("%w: %s profile %q has empty include", ErrInvalidConfig, path, profileName)
		}
		included, err := resolveProfile(doc, path, includeName, nextStack)
		if err != nil {
			return resolvedProfile{}, err
		}
		maps.Copy(result.secrets, included.secrets)
		if included.reason != "" {
			result.reason = included.reason
		}
		if included.ttl != 0 {
			result.ttl = included.ttl
		}
	}

	ttl, err := parseTTL(rawProfile.TTL, path, profileName)
	if err != nil {
		return resolvedProfile{}, err
	}
	if rawProfile.Reason != "" {
		result.reason = rawProfile.Reason
	}
	if ttl != 0 {
		result.ttl = ttl
	}
	if err := mergeSecrets(result.secrets, rawProfile.Secrets, result.account, path, profileName); err != nil {
		return resolvedProfile{}, err
	}
	if len(result.secrets) == 0 {
		return resolvedProfile{}, fmt.Errorf("%w: %s profile %q must define or include at least one secret", ErrInvalidConfig, path, profileName)
	}
	return result, nil
}

func Find(configPath string, startDir string) (string, error) {
	if configPath != "" {
		path, err := filepath.Abs(configPath)
		if err != nil {
			return "", fmt.Errorf("resolve profile config path %q: %w", configPath, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		if info.IsDir() {
			return "", fmt.Errorf("%w: %s is a directory", ErrInvalidConfig, path)
		}
		return path, nil
	}

	dir := startDir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get current directory: %w", err)
		}
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve profile search dir %q: %w", startDir, err)
	}

	for {
		for _, name := range []string{"agent-secret.yml", ".agent-secret.yml"} {
			candidate := filepath.Join(dir, name)
			info, err := os.Stat(candidate)
			if err == nil && !info.IsDir() {
				return candidate, nil
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("stat profile config %s: %w", candidate, err)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: expected agent-secret.yml or .agent-secret.yml in the current directory or a parent", ErrConfigNotFound)
		}
		dir = parent
	}
}

func parseTTL(raw string, path string, profileName string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: %s profile %q has invalid ttl %q: %w", ErrInvalidConfig, path, profileName, raw, err)
	}
	return ttl, nil
}

func mergeSecrets(secrets map[string]resolvedSecret, raw map[string]secretYAML, account string, path string, profileName string) error {
	for alias, spec := range raw {
		if spec.Ref == "" {
			return fmt.Errorf("%w: %s profile %q secret %q has empty ref", ErrInvalidConfig, path, profileName, alias)
		}
		secrets[alias] = resolvedSecret{
			account: effectiveAccount(account, spec.Account),
			ref:     spec.Ref,
		}
	}
	return nil
}

func sortedSecrets(raw map[string]resolvedSecret, path string, profileName string) ([]request.SecretSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s profile %q must define or include at least one secret", ErrInvalidConfig, path, profileName)
	}

	aliases := make([]string, 0, len(raw))
	for alias := range raw {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)

	secrets := make([]request.SecretSpec, 0, len(aliases))
	for _, alias := range aliases {
		spec := raw[alias]
		secrets = append(secrets, request.SecretSpec{
			Alias:   alias,
			Ref:     spec.ref,
			Account: spec.account,
		})
	}
	return secrets, nil
}

func effectiveAccount(defaultAccount string, overrideAccount string) string {
	override := strings.TrimSpace(overrideAccount)
	if override != "" {
		return override
	}
	return strings.TrimSpace(defaultAccount)
}
