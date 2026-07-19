package gcpcompat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareTokenFileDeliveryWritesPrivateCloudSDKStateAndCleansUp(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "gcp")
	delivery, err := PrepareTokenFileDelivery(base, "fixture-beta", Token{
		AccessToken: "synthetic-access-token",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("PrepareTokenFileDelivery returned error: %v", err)
	}
	configDir := delivery.Env[EnvCloudSDKConfig]
	tokenPath := delivery.Env[EnvCloudSDKAccessTokenFile]
	if configDir == "" || tokenPath == "" {
		t.Fatalf("delivery env missing paths: %+v", delivery.Env)
	}
	if delivery.Env[EnvCloudSDKCoreProject] != "fixture-beta" {
		t.Fatalf("project env = %q", delivery.Env[EnvCloudSDKCoreProject])
	}
	requireMode(t, base, 0o700)
	requireMode(t, filepath.Dir(tokenPath), 0o700)
	requireMode(t, configDir, 0o700)
	requireMode(t, tokenPath, 0o600)

	data, err := os.ReadFile(tokenPath) //nolint:gosec // G304: test reads the token path created by PrepareTokenFileDelivery under t.TempDir.
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != "synthetic-access-token" {
		t.Fatalf("token file = %q", string(data))
	}
	configData, err := os.ReadFile(filepath.Join(configDir, "configurations", "config_default")) //nolint:gosec // G304: test reads isolated config created under t.TempDir.
	if err != nil {
		t.Fatalf("read config_default: %v", err)
	}
	if string(configData) != "[core]\nproject = fixture-beta\n" {
		t.Fatalf("config_default = %q", string(configData))
	}

	delivery.Cleanup()
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token path survived cleanup: %v", err)
	}
}

func TestCleanupStaleRemovesBrokerOwnedChildren(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "gcp")
	stale := filepath.Join(base, "delivery-stale")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatalf("create stale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stale, "access-token"), []byte("synthetic"), 0o600); err != nil {
		t.Fatalf("write stale token: %v", err)
	}
	if err := CleanupStale(base); err != nil {
		t.Fatalf("CleanupStale returned error: %v", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("base entries after cleanup = %v", entries)
	}
	requireMode(t, base, 0o700)
}

func TestPrepareTokenFileDeliveryRejectsMissingInputsBeforeWriting(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "gcp")
	_, err := PrepareTokenFileDelivery(base, "fixture-beta", Token{ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "access token is empty") {
		t.Fatalf("empty token error = %v", err)
	}
	if _, statErr := os.Stat(base); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("base created after empty token error: %v", statErr)
	}

	_, err = PrepareTokenFileDelivery(base, "", Token{AccessToken: "synthetic", ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "project is required") {
		t.Fatalf("empty project error = %v", err)
	}
	if _, statErr := os.Stat(base); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("base created after empty project error: %v", statErr)
	}

	_, err = PrepareTokenFileDelivery("", "fixture-beta", Token{AccessToken: "synthetic", ExpiresAt: time.Now().Add(time.Minute)})
	if err == nil || !strings.Contains(err.Error(), "base directory is required") {
		t.Fatalf("empty base error = %v", err)
	}
}

func TestDeliveryCleanupIsIdempotentAndNilSafe(t *testing.T) {
	t.Parallel()

	var delivery *Delivery
	delivery.Cleanup()

	base := filepath.Join(t.TempDir(), "gcp")
	delivery, err := PrepareTokenFileDelivery(base, "fixture-beta", Token{
		AccessToken: "synthetic",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("PrepareTokenFileDelivery returned error: %v", err)
	}
	tokenPath := delivery.Env[EnvCloudSDKAccessTokenFile]
	delivery.Cleanup()
	delivery.Cleanup()
	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token path after double cleanup = %v, want not exist", err)
	}
}

func TestCleanupStaleCreatesMissingBaseAndDefaultBaseDirIsUserScoped(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "missing", "gcp")
	if err := CleanupStale(base); err != nil {
		t.Fatalf("CleanupStale returned error: %v", err)
	}
	requireMode(t, base, 0o700)

	defaultBase := DefaultBaseDir()
	if !filepath.IsAbs(defaultBase) || !strings.Contains(defaultBase, "agent-secret-gcp-") {
		t.Fatalf("DefaultBaseDir = %q, want absolute agent-secret path", defaultBase)
	}
}

func TestBaseDirRejectsFilePath(t *testing.T) {
	t.Parallel()

	base := filepath.Join(t.TempDir(), "base")
	if err := os.WriteFile(base, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write base file: %v", err)
	}
	_, err := PrepareTokenFileDelivery(base, "fixture-beta", Token{
		AccessToken: "synthetic",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	if err == nil {
		t.Fatal("PrepareTokenFileDelivery accepted file base path")
	}
	if err := CleanupStale(base); err == nil {
		t.Fatal("CleanupStale accepted file base path")
	}
}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %s, want %s", path, got, want)
	}
}
