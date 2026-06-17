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
	"github.com/kovyrin/agent-secret/internal/secretref"
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
	Sources    Sources
}

type ConfigInfo struct {
	SourcePath     string        `json:"source_path"`
	Version        int           `json:"version"`
	Account        string        `json:"account,omitempty"`
	DefaultProfile string        `json:"default_profile,omitempty"`
	Sources        Sources       `json:"sources,omitzero"`
	Profiles       []ProfileInfo `json:"profiles"`
}

type ProfileInfo struct {
	Name    string               `json:"name"`
	Default bool                 `json:"default"`
	Account string               `json:"account,omitempty"`
	Reason  string               `json:"reason,omitempty"`
	TTL     string               `json:"ttl,omitempty"`
	Include []string             `json:"include,omitempty"`
	Session *SessionInfo         `json:"session,omitempty"`
	Secrets []request.SecretSpec `json:"secrets,omitempty"`
}

type Profile struct {
	Name           string
	SourcePath     string
	Account        string
	Sources        Sources
	Reason         string
	Secrets        []request.SecretSpec
	TTL            time.Duration
	SessionBinding *request.SessionBindingPolicy
}

type SessionInfo struct {
	Bind *request.SessionBindingPolicy `json:"bind,omitempty"`
}

type configFile struct {
	Version        int                    `yaml:"version"`
	Account        string                 `yaml:"account"`
	DefaultProfile string                 `yaml:"default_profile"`
	Sources        sourceConfigYAML       `yaml:"sources"`
	Profiles       map[string]profileYAML `yaml:"profiles"`
}

type Sources struct {
	Bitwarden map[string]request.BitwardenSource `json:"bitwarden,omitempty"`
}

func (s Sources) IsZero() bool {
	return len(s.Bitwarden) == 0
}

type sourceConfigYAML struct {
	Bitwarden map[string]bitwardenSourceYAML `yaml:"bitwarden"`
}

type bitwardenSourceYAML struct {
	Kind        string `yaml:"kind"`
	TokenAlias  string `yaml:"token_alias"`
	APIURL      string `yaml:"api_url"`
	IdentityURL string `yaml:"identity_url"`
}

type profileYAML struct {
	Account string                `yaml:"account"`
	Include []string              `yaml:"include"`
	Reason  string                `yaml:"reason"`
	Session profileSessionYAML    `yaml:"session"`
	Secrets map[string]secretYAML `yaml:"secrets"`
	TTL     string                `yaml:"ttl"`
}

type resolvedProfile struct {
	account        string
	reason         string
	secrets        map[string]resolvedSecret
	ttl            time.Duration
	sessionBinding *request.SessionBindingPolicy
}

type resolvedSecret struct {
	account   string
	ref       string
	source    string
	bitwarden request.BitwardenSource
}

type secretYAML struct {
	Ref     string
	Account string
	Source  string
}

type profileSessionYAML struct {
	Bind sessionBindYAML `yaml:"bind"`
}

type sessionBindYAML struct {
	policy request.SessionBindingPolicy
	set    bool
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
		case "source":
			if err := item.Decode(&s.Source); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown secret field %q", key)
		}
	}
	return nil
}

func (s *sessionBindYAML) policyPointer() *request.SessionBindingPolicy {
	if !s.set {
		return nil
	}
	policy := s.policy
	return &policy
}

func (s *sessionBindYAML) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var raw string
		if err := value.Decode(&raw); err != nil {
			return err
		}
		return s.setFromScalar(raw)
	case yaml.MappingNode:
		return s.unmarshalMapping(value)
	case yaml.DocumentNode, yaml.SequenceNode, yaml.AliasNode:
		return errors.New("session bind must be auto, parent, or a mapping")
	}
	return errors.New("session bind must be auto, parent, or a mapping")
}

func (s *sessionBindYAML) setFromScalar(raw string) error {
	switch strings.TrimSpace(raw) {
	case "auto":
		s.policy = request.DefaultSessionBindingPolicy()
	case "parent":
		policy, err := request.NewSessionAncestorBinding(1)
		if err != nil {
			return err
		}
		s.policy = policy
	default:
		return errors.New("session bind must be auto, parent, or a mapping")
	}
	s.set = true
	return nil
}

func (s *sessionBindYAML) unmarshalMapping(value *yaml.Node) error {
	var ancestorDepth int
	var ancestorName string
	ancestorDepthSet := false
	ancestorNameSet := false
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		item := value.Content[i+1]
		switch key {
		case "ancestor":
			ancestorDepthSet = true
			if err := item.Decode(&ancestorDepth); err != nil {
				return err
			}
		case "ancestor_name":
			ancestorNameSet = true
			if err := item.Decode(&ancestorName); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown session bind field %q", key)
		}
	}
	if ancestorDepthSet == ancestorNameSet {
		return errors.New("session bind mapping must set exactly one of ancestor or ancestor_name")
	}
	var (
		policy request.SessionBindingPolicy
		err    error
	)
	if ancestorDepthSet {
		policy, err = request.NewSessionAncestorBinding(ancestorDepth)
	} else {
		policy, err = request.NewSessionAncestorNameBinding(ancestorName)
	}
	if err != nil {
		return err
	}
	s.policy = policy
	s.set = true
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
	sources, err := normalizeSources(doc.Sources)
	if err != nil {
		return Profile{}, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
	}

	profileName := opts.Name
	if profileName == "" {
		profileName = doc.DefaultProfile
	}
	if profileName == "" {
		return Profile{}, fmt.Errorf("%w: %s default_profile is required when no profile name is provided", ErrProfileNotFound, path)
	}

	resolved, err := newProfileResolver(doc, path, sources).resolve(profileName, nil)
	if err != nil {
		return Profile{}, err
	}
	secrets, err := sortedSecrets(resolved.secrets, path, profileName)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		Name:           profileName,
		SourcePath:     path,
		Account:        resolved.account,
		Sources:        sources,
		Reason:         resolved.reason,
		Secrets:        secrets,
		TTL:            resolved.ttl,
		SessionBinding: cloneSessionBindingPolicy(resolved.sessionBinding),
	}, nil
}

func LoadMetadata(opts LoadOptions) (Metadata, error) {
	path, doc, err := loadConfigFile(opts)
	if err != nil {
		return Metadata{}, err
	}
	sources, err := normalizeSources(doc.Sources)
	if err != nil {
		return Metadata{}, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
	}
	return Metadata{
		SourcePath: path,
		Account:    strings.TrimSpace(doc.Account),
		Sources:    sources,
	}, nil
}

func Inspect(opts LoadOptions) (ConfigInfo, error) {
	path, doc, err := loadConfigFile(opts)
	if err != nil {
		return ConfigInfo{}, err
	}
	sources, err := normalizeSources(doc.Sources)
	if err != nil {
		return ConfigInfo{}, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
	}

	info := ConfigInfo{
		SourcePath:     path,
		Version:        doc.Version,
		Account:        strings.TrimSpace(doc.Account),
		DefaultProfile: strings.TrimSpace(doc.DefaultProfile),
		Sources:        sources,
		Profiles:       make([]ProfileInfo, 0, len(doc.Profiles)),
	}
	resolver := newProfileResolver(doc, path, sources)
	names := make([]string, 0, len(doc.Profiles))
	for name := range doc.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		rawProfile := doc.Profiles[name]
		resolved, err := resolver.resolve(name, nil)
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
			Session: sessionInfo(resolved.sessionBinding),
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
	sources      Sources
	memo         map[string]resolvedProfile
	includeCount int
}

func newProfileResolver(doc configFile, path string, sources Sources) *profileResolver {
	return &profileResolver{
		doc:     doc,
		path:    path,
		sources: cloneSources(sources),
		memo:    make(map[string]resolvedProfile),
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
		if included.sessionBinding != nil {
			result.sessionBinding = cloneSessionBindingPolicy(included.sessionBinding)
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
	if policy := rawProfile.Session.Bind.policyPointer(); policy != nil {
		result.sessionBinding = policy
	}
	if err := mergeSecrets(result.secrets, rawProfile.Secrets, result.account, r.sources, r.path, profileName); err != nil {
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
		account:        profile.account,
		reason:         profile.reason,
		secrets:        cloneResolvedSecrets(profile.secrets),
		ttl:            profile.ttl,
		sessionBinding: cloneSessionBindingPolicy(profile.sessionBinding),
	}
}

func sessionInfo(policy *request.SessionBindingPolicy) *SessionInfo {
	if policy == nil {
		return nil
	}
	return &SessionInfo{Bind: cloneSessionBindingPolicy(policy)}
}

func cloneSessionBindingPolicy(policy *request.SessionBindingPolicy) *request.SessionBindingPolicy {
	if policy == nil {
		return nil
	}
	clone := *policy
	return &clone
}

func cloneResolvedSecrets(secrets map[string]resolvedSecret) map[string]resolvedSecret {
	return maps.Clone(secrets)
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

func mergeSecrets(
	secrets map[string]resolvedSecret,
	raw map[string]secretYAML,
	account string,
	sources Sources,
	path string,
	profileName string,
) error {
	for alias, spec := range raw {
		if spec.Ref == "" {
			return fmt.Errorf("%w: %s profile %q secret %q has empty ref", ErrInvalidConfig, path, profileName, alias)
		}
		source, bitwarden, err := resolveSecretSource(spec, sources, path, profileName, alias)
		if err != nil {
			return err
		}
		secrets[alias] = resolvedSecret{
			account:   effectiveAccount(account, spec.Account),
			ref:       spec.Ref,
			source:    source,
			bitwarden: bitwarden,
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
			Alias:     alias,
			Ref:       spec.ref,
			Account:   spec.account,
			Source:    spec.source,
			Bitwarden: spec.bitwarden,
		})
	}
	return secrets, nil
}

func resolveSecretSource(
	spec secretYAML,
	sources Sources,
	path string,
	profileName string,
	alias string,
) (string, request.BitwardenSource, error) {
	source := strings.TrimSpace(spec.Source)
	parsed, err := secretref.Parse(spec.Ref)
	if err != nil {
		if secretref.IsBitwardenSecretsManager(spec.Ref) {
			return "", request.BitwardenSource{}, fmt.Errorf(
				"%w: %s profile %q secret %q has invalid Bitwarden ref: %w",
				ErrInvalidConfig,
				path,
				profileName,
				alias,
				err,
			)
		}
		if source != "" {
			return "", request.BitwardenSource{}, fmt.Errorf(
				"%w: %s profile %q secret %q source is only valid for Bitwarden refs",
				ErrInvalidConfig,
				path,
				profileName,
				alias,
			)
		}
		return "", request.BitwardenSource{}, nil
	}
	if parsed.Provider != secretref.ProviderBitwardenSecretsManager {
		if source != "" {
			return "", request.BitwardenSource{}, fmt.Errorf(
				"%w: %s profile %q secret %q source is only valid for Bitwarden refs",
				ErrInvalidConfig,
				path,
				profileName,
				alias,
			)
		}
		return "", request.BitwardenSource{}, nil
	}
	if parsed.Source != "" {
		if source != "" && source != parsed.Source {
			return "", request.BitwardenSource{}, fmt.Errorf(
				"%w: %s profile %q secret %q source %q does not match ref source %q",
				ErrInvalidConfig,
				path,
				profileName,
				alias,
				source,
				parsed.Source,
			)
		}
		source = parsed.Source
	}
	if source == "" {
		if inferred, ok := singleBitwardenSource(sources); ok {
			source = inferred.Alias
		} else if len(sources.Bitwarden) > 1 {
			return "", request.BitwardenSource{}, fmt.Errorf(
				"%w: %s profile %q secret %q must set source when multiple Bitwarden sources are configured",
				ErrInvalidConfig,
				path,
				profileName,
				alias,
			)
		}
	}
	if source == "" {
		return "", request.BitwardenSource{}, nil
	}
	normalizedSource, err := secretref.NormalizeSourceAlias(source)
	if err != nil {
		return "", request.BitwardenSource{}, fmt.Errorf(
			"%w: %s profile %q secret %q has invalid Bitwarden source: %w",
			ErrInvalidConfig,
			path,
			profileName,
			alias,
			err,
		)
	}
	if configured, ok := sources.Bitwarden[normalizedSource]; ok {
		return normalizedSource, configured, nil
	}
	if len(sources.Bitwarden) > 0 {
		return "", request.BitwardenSource{}, fmt.Errorf(
			"%w: %s profile %q secret %q references unknown Bitwarden source %q",
			ErrInvalidConfig,
			path,
			profileName,
			alias,
			normalizedSource,
		)
	}
	return normalizedSource, request.BitwardenSource{Alias: normalizedSource, TokenAlias: normalizedSource}, nil
}

func normalizeSources(raw sourceConfigYAML) (Sources, error) {
	out := Sources{}
	if len(raw.Bitwarden) == 0 {
		return out, nil
	}
	out.Bitwarden = make(map[string]request.BitwardenSource, len(raw.Bitwarden))
	for rawAlias, spec := range raw.Bitwarden {
		source, err := normalizeBitwardenSource(rawAlias, spec)
		if err != nil {
			return Sources{}, err
		}
		out.Bitwarden[source.Alias] = source
	}
	return out, nil
}

func normalizeBitwardenSource(rawAlias string, spec bitwardenSourceYAML) (request.BitwardenSource, error) {
	alias, err := secretref.NormalizeSourceAlias(rawAlias)
	if err != nil {
		return request.BitwardenSource{}, fmt.Errorf("invalid bitwarden source alias %q: %w", rawAlias, err)
	}
	kind := strings.TrimSpace(spec.Kind)
	if kind == "" {
		kind = secretref.BitwardenSecretsManagerSourceKind
	}
	if kind != secretref.BitwardenSecretsManagerSourceKind {
		return request.BitwardenSource{}, fmt.Errorf("bitwarden source %q kind must be %q", alias, secretref.BitwardenSecretsManagerSourceKind)
	}
	tokenAlias := strings.TrimSpace(spec.TokenAlias)
	if tokenAlias == "" {
		tokenAlias = alias
	}
	tokenAlias, err = secretref.NormalizeSourceAlias(tokenAlias)
	if err != nil {
		return request.BitwardenSource{}, fmt.Errorf("bitwarden source %q has invalid token_alias: %w", alias, err)
	}
	if strings.TrimSpace(spec.APIURL) != "" || strings.TrimSpace(spec.IdentityURL) != "" {
		return request.BitwardenSource{}, fmt.Errorf("bitwarden source %q custom endpoints are not supported in v1", alias)
	}
	return request.BitwardenSource{
		Alias:      alias,
		TokenAlias: tokenAlias,
	}, nil
}

func singleBitwardenSource(sources Sources) (request.BitwardenSource, bool) {
	if len(sources.Bitwarden) != 1 {
		return request.BitwardenSource{}, false
	}
	for _, source := range sources.Bitwarden {
		return source, true
	}
	return request.BitwardenSource{}, false
}

func cloneSources(sources Sources) Sources {
	out := Sources{}
	if len(sources.Bitwarden) > 0 {
		out.Bitwarden = maps.Clone(sources.Bitwarden)
	}
	return out
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
