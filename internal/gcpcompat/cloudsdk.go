package gcpcompat

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	EnvCloudSDKConfig          = "CLOUDSDK_CONFIG"
	EnvCloudSDKActiveConfig    = "CLOUDSDK_ACTIVE_CONFIG_NAME"
	EnvCloudSDKAccessTokenFile = "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE" //nolint:gosec // G101: environment variable name, not a token.
	EnvCloudSDKCoreProject     = "CLOUDSDK_CORE_PROJECT"
)

type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

type Delivery struct {
	Env       map[string]string
	ExpiresAt time.Time
	dir       string
}

func PrepareTokenFileDelivery(baseDir string, project string, token Token) (*Delivery, error) {
	if token.AccessToken == "" {
		return nil, errors.New("GCP access token is empty")
	}
	if project == "" {
		return nil, errors.New("GCP project is required")
	}
	if err := prepareBaseDir(baseDir); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(baseDir, "delivery-")
	if err != nil {
		return nil, fmt.Errorf("create GCP token delivery directory: %w", err)
	}
	delivery := &Delivery{dir: dir, ExpiresAt: token.ExpiresAt}
	committed := false
	defer func() {
		if !committed {
			delivery.Cleanup()
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: token directories must be private but searchable by owner.
		return nil, fmt.Errorf("chmod GCP token delivery directory: %w", err)
	}
	configDir := filepath.Join(dir, "cloudsdk")
	if err := os.MkdirAll(filepath.Join(configDir, "configurations"), 0o700); err != nil {
		return nil, fmt.Errorf("create isolated Cloud SDK config: %w", err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil { //nolint:gosec // G302: Cloud SDK config directory must be private but searchable by owner.
		return nil, fmt.Errorf("chmod isolated Cloud SDK config: %w", err)
	}
	configPath := filepath.Join(configDir, "configurations", "config_default")
	configData := []byte("[core]\nproject = " + project + "\n")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		return nil, fmt.Errorf("write isolated Cloud SDK default project: %w", err)
	}
	tokenPath := filepath.Join(dir, "access-token")
	if err := os.WriteFile(tokenPath, []byte(token.AccessToken), 0o600); err != nil {
		return nil, fmt.Errorf("write GCP access token file: %w", err)
	}
	delivery.Env = map[string]string{
		EnvCloudSDKConfig:          configDir,
		EnvCloudSDKActiveConfig:    "default",
		EnvCloudSDKAccessTokenFile: tokenPath,
		EnvCloudSDKCoreProject:     project,
	}
	committed = true
	return delivery, nil
}

func CleanupStale(baseDir string) error {
	if err := prepareBaseDir(baseDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return fmt.Errorf("read GCP token delivery base directory: %w", err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(baseDir, entry.Name())); err != nil {
			return fmt.Errorf("remove stale GCP token delivery %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func DefaultBaseDir() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("agent-secret-gcp-%d", os.Getuid()))
}

func (d *Delivery) Cleanup() {
	if d == nil || d.dir == "" {
		return
	}
	_ = os.RemoveAll(d.dir)
	d.dir = ""
}

func prepareBaseDir(path string) error {
	if path == "" {
		return errors.New("GCP token delivery base directory is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create GCP token delivery base directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // G302: token base directory must be private but searchable by owner.
		return fmt.Errorf("chmod GCP token delivery base directory: %w", err)
	}
	return nil
}
