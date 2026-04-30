package profileconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	Reason     string
	Secrets    []request.SecretSpec
	TTL        time.Duration
}

type configFile struct {
	Version  int                    `yaml:"version"`
	Profiles map[string]profileYAML `yaml:"profiles"`
}

type profileYAML struct {
	Reason  string            `yaml:"reason"`
	Secrets map[string]string `yaml:"secrets"`
	TTL     string            `yaml:"ttl"`
}

func Load(opts LoadOptions) (Profile, error) {
	if opts.Name == "" {
		return Profile{}, fmt.Errorf("%w: profile name is required", ErrProfileNotFound)
	}

	path, err := Find(opts.ConfigPath, opts.StartDir)
	if err != nil {
		return Profile{}, err
	}

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

	rawProfile, ok := doc.Profiles[opts.Name]
	if !ok {
		return Profile{}, fmt.Errorf("%w: %q in %s", ErrProfileNotFound, opts.Name, path)
	}

	ttl, err := parseTTL(rawProfile.TTL, path, opts.Name)
	if err != nil {
		return Profile{}, err
	}
	secrets, err := parseSecrets(rawProfile.Secrets, path, opts.Name)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		Name:       opts.Name,
		SourcePath: path,
		Reason:     rawProfile.Reason,
		Secrets:    secrets,
		TTL:        ttl,
	}, nil
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

func parseSecrets(raw map[string]string, path string, profileName string) ([]request.SecretSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s profile %q must define at least one secret", ErrInvalidConfig, path, profileName)
	}

	aliases := make([]string, 0, len(raw))
	for alias := range raw {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)

	secrets := make([]request.SecretSpec, 0, len(aliases))
	for _, alias := range aliases {
		ref := raw[alias]
		if ref == "" {
			return nil, fmt.Errorf("%w: %s profile %q secret %q has empty ref", ErrInvalidConfig, path, profileName, alias)
		}
		secrets = append(secrets, request.SecretSpec{Alias: alias, Ref: ref})
	}
	return secrets, nil
}
