package profileconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
	yaml "gopkg.in/yaml.v3"
)

const currentVersion = 1
const maxConfigFileBytes = 1 << 20
const maxProfileIncludeDepth = 32
const maxProfileIncludeCount = 128

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

type Metadata struct {
	SourcePath string
	Account    string
}

type ConfigInfo struct {
	SourcePath     string        `json:"source_path"`
	Version        int           `json:"version"`
	Account        string        `json:"account,omitempty"`
	DefaultProfile string        `json:"default_profile,omitempty"`
	Profiles       []ProfileInfo `json:"profiles"`
}

type ProfileInfo struct {
	Name    string               `json:"name"`
	Default bool                 `json:"default"`
	Account string               `json:"account,omitempty"`
	Reason  string               `json:"reason,omitempty"`
	TTL     string               `json:"ttl,omitempty"`
	Include []string             `json:"include,omitempty"`
	Secrets []request.SecretSpec `json:"secrets,omitempty"`
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
	path, doc, err := loadConfigFile(opts)
	if err != nil {
		return Profile{}, err
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

	resolved, err := newProfileResolver(doc, path).resolve(profileName, nil)
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

func LoadMetadata(opts LoadOptions) (Metadata, error) {
	path, doc, err := loadConfigFile(opts)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		SourcePath: path,
		Account:    strings.TrimSpace(doc.Account),
	}, nil
}

func Inspect(opts LoadOptions) (ConfigInfo, error) {
	path, doc, err := loadConfigFile(opts)
	if err != nil {
		return ConfigInfo{}, err
	}

	info := ConfigInfo{
		SourcePath:     path,
		Version:        doc.Version,
		Account:        strings.TrimSpace(doc.Account),
		DefaultProfile: strings.TrimSpace(doc.DefaultProfile),
		Profiles:       make([]ProfileInfo, 0, len(doc.Profiles)),
	}
	names := make([]string, 0, len(doc.Profiles))
	for name := range doc.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		rawProfile := doc.Profiles[name]
		resolved, err := newProfileResolver(doc, path).resolve(name, nil)
		if err != nil {
			return ConfigInfo{}, err
		}
		secrets, err := sortedSecrets(resolved.secrets, path, name)
		if err != nil {
			return ConfigInfo{}, err
		}
		profile := ProfileInfo{
			Name:    name,
			Default: name == info.DefaultProfile,
			Account: resolved.account,
			Reason:  resolved.reason,
			Include: trimmedList(rawProfile.Include),
			Secrets: secrets,
		}
		if resolved.ttl != 0 {
			profile.TTL = resolved.ttl.String()
		}
		info.Profiles = append(info.Profiles, profile)
	}
	return info, nil
}

func loadConfigFile(opts LoadOptions) (string, configFile, error) {
	path, err := Find(opts.ConfigPath, opts.StartDir)
	if err != nil {
		return "", configFile{}, err
	}

	data, err := readConfigFile(path)
	if err != nil {
		return "", configFile{}, err
	}

	var doc configFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return "", configFile{}, fmt.Errorf("%w: parse %s: %w", ErrInvalidConfig, path, err)
	}
	if doc.Version != currentVersion {
		return "", configFile{}, fmt.Errorf("%w: %s version must be %d", ErrInvalidConfig, path, currentVersion)
	}
	return path, doc, nil
}

func readConfigFile(path string) ([]byte, error) {
	//nolint:gosec // G304: config path is selected from explicit project config discovery and parsed as configuration only.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read profile config %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat profile config %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s must be a regular file", ErrInvalidConfig, path)
	}
	if info.Size() > maxConfigFileBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidConfig, path, maxConfigFileBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read profile config %s: %w", path, err)
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidConfig, path, maxConfigFileBytes)
	}
	return data, nil
}

type profileResolver struct {
	doc          configFile
	path         string
	memo         map[string]resolvedProfile
	includeCount int
}

func newProfileResolver(doc configFile, path string) *profileResolver {
	return &profileResolver{
		doc:  doc,
		path: path,
		memo: make(map[string]resolvedProfile),
	}
}

func (r *profileResolver) resolve(profileName string, stack []string) (resolvedProfile, error) {
	if cached, ok := r.memo[profileName]; ok {
		return cloneResolvedProfile(cached), nil
	}
	if len(stack) >= maxProfileIncludeDepth {
		return resolvedProfile{}, fmt.Errorf(
			"%w: %s profile include depth exceeds %d at %q",
			ErrInvalidConfig,
			r.path,
			maxProfileIncludeDepth,
			profileName,
		)
	}

	rawProfile, ok := r.doc.Profiles[profileName]
	if !ok {
		return resolvedProfile{}, fmt.Errorf("%w: %q in %s", ErrProfileNotFound, profileName, r.path)
	}
	if slices.Contains(stack, profileName) {
		cycle := append(slices.Clone(stack), profileName)
		return resolvedProfile{}, fmt.Errorf("%w: %s profile include cycle: %s", ErrInvalidConfig, r.path, strings.Join(cycle, " -> "))
	}

	result := resolvedProfile{
		account: effectiveAccount(r.doc.Account, rawProfile.Account),
		secrets: make(map[string]resolvedSecret),
	}
	nextStack := append(slices.Clone(stack), profileName)
	for _, includeName := range rawProfile.Include {
		includeName = strings.TrimSpace(includeName)
		if includeName == "" {
			return resolvedProfile{}, fmt.Errorf("%w: %s profile %q has empty include", ErrInvalidConfig, r.path, profileName)
		}
		r.includeCount++
		if r.includeCount > maxProfileIncludeCount {
			return resolvedProfile{}, fmt.Errorf(
				"%w: %s profile include count exceeds %d",
				ErrInvalidConfig,
				r.path,
				maxProfileIncludeCount,
			)
		}
		included, err := r.resolve(includeName, nextStack)
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

	ttl, err := parseTTL(rawProfile.TTL, r.path, profileName)
	if err != nil {
		return resolvedProfile{}, err
	}
	if rawProfile.Reason != "" {
		result.reason = rawProfile.Reason
	}
	if ttl != 0 {
		result.ttl = ttl
	}
	if err := mergeSecrets(result.secrets, rawProfile.Secrets, result.account, r.path, profileName); err != nil {
		return resolvedProfile{}, err
	}
	if len(result.secrets) == 0 {
		return resolvedProfile{}, fmt.Errorf("%w: %s profile %q must define or include at least one secret", ErrInvalidConfig, r.path, profileName)
	}
	r.memo[profileName] = cloneResolvedProfile(result)
	return result, nil
}

func cloneResolvedProfile(profile resolvedProfile) resolvedProfile {
	return resolvedProfile{
		account: profile.account,
		reason:  profile.reason,
		secrets: maps.Clone(profile.secrets),
		ttl:     profile.ttl,
	}
}

func Find(configPath string, startDir string) (string, error) {
	if configPath != "" {
		return findExplicit(configPath)
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
			if err == nil {
				if info.Mode().IsRegular() {
					return candidate, nil
				}
				if !info.IsDir() {
					return "", fmt.Errorf("%w: %s must be a regular file", ErrInvalidConfig, candidate)
				}
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

func findExplicit(configPath string) (string, error) {
	path, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve profile config path %q: %w", configPath, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("stat profile config %s: %w", path, err)
		}
		return "", fmt.Errorf("%w: %s", ErrConfigNotFound, path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s must be a regular file", ErrInvalidConfig, path)
	}
	return path, nil
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

func trimmedList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
