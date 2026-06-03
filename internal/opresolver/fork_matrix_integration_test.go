//go:build integration

package opresolver

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
)

const (
	defaultLiveForkPrimaryAccount = "my.1password.com"
	defaultLiveForkPrimaryRef     = "op://Agent Secret Integration/Test Secret/password"
	defaultLiveForkPrimaryItemRef = "op://Agent Secret Integration/Test Secret"
	defaultLiveForkPrimaryTextRef = "op://Agent Secret Integration/Test Secret/test.txt"
	defaultLiveForkFixtureAccount = "fixture.1password.com"
	defaultLiveForkFixtureRef     = "op://Employee/Agent Secret Test/password"
)

type liveForkMatrixConfig struct {
	primaryAccount string
	primaryRef     string
	primaryItemRef string
	primaryTextRef string
	fixtureAccount string
	fixtureRef     string
}

func TestLiveDesktopForkRemovalMatrix(t *testing.T) {
	cfg := loadLiveForkMatrixConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pool := NewDesktopPoolWithOptions(DesktopPoolOptions{
		IntegrationName:    "Agent Secret Broker SDK Fork Removal Matrix",
		IntegrationVersion: "integration-test",
		InitTimeout:        45 * time.Second,
	})

	primary := resolveLiveMatrixSecret(t, ctx, pool, cfg.primaryRef, cfg.primaryAccount)
	fixture := resolveLiveMatrixSecret(t, ctx, pool, cfg.fixtureRef, cfg.fixtureAccount)
	if primary == fixture {
		t.Fatalf("primary and fixture refs resolved to the same value; use distinct synthetic fixture values to prove account isolation")
	}

	againPrimary := resolveLiveMatrixSecret(t, ctx, pool, cfg.primaryRef, cfg.primaryAccount)
	if againPrimary != primary {
		t.Fatalf("primary ref changed after resolving fixture account; account switching is not stable")
	}

	againFixture := resolveLiveMatrixSecret(t, ctx, pool, cfg.fixtureRef, cfg.fixtureAccount)
	if againFixture != fixture {
		t.Fatalf("fixture ref changed after switching back to primary account; account switching is not stable")
	}

	itemRef, err := itemmetadata.ParseRef(cfg.primaryItemRef)
	if err != nil {
		t.Fatalf("parse primary item ref: %v", err)
	}
	metadata, err := pool.DescribeItem(ctx, itemRef, cfg.primaryAccount)
	if err != nil {
		t.Fatalf("describe primary item metadata: %v", err)
	}
	assertLiveMatrixMetadata(t, metadata, cfg.primaryAccount, itemRef)
	assertLiveMatrixField(t, metadata, cfg.primaryRef)

	text := resolveLiveMatrixSecret(t, ctx, pool, cfg.primaryTextRef, cfg.primaryAccount)
	if text == "" {
		t.Fatalf("text file ref resolved to an empty value")
	}
}

func TestLiveDesktopResolverOutlivesInitializationContext(t *testing.T) {
	cfg := loadLiveForkMatrixConfig(t)

	initCtx, cancelInit := context.WithTimeout(context.Background(), 45*time.Second)
	resolver, err := NewDesktopResolver(initCtx, ClientOptions{
		Account:            cfg.primaryAccount,
		IntegrationName:    "Agent Secret Broker SDK Lifetime Matrix",
		IntegrationVersion: "integration-test",
	})
	cancelInit()
	if err != nil {
		t.Fatalf("create desktop resolver: %v", err)
	}

	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelResolve()

	secret, err := resolver.ResolveSecret(resolveCtx, cfg.primaryRef)
	if err != nil {
		t.Fatalf("resolve after initialization context cancellation: %v", err)
	}
	metadata := secret.Metadata()
	if metadata.Length == 0 || metadata.SHA256 == "" {
		t.Fatalf("resolved secret metadata is incomplete after initialization context cancellation: %+v", metadata)
	}

	itemRef, err := itemmetadata.ParseRef(cfg.primaryItemRef)
	if err != nil {
		t.Fatalf("parse primary item ref: %v", err)
	}
	item, err := resolver.DescribeItem(resolveCtx, itemRef, cfg.primaryAccount)
	if err != nil {
		t.Fatalf("describe metadata after initialization context cancellation: %v", err)
	}
	assertLiveMatrixMetadata(t, item, cfg.primaryAccount, itemRef)
}

func loadLiveForkMatrixConfig(t *testing.T) liveForkMatrixConfig {
	t.Helper()
	if os.Getenv("AGENT_SECRET_LIVE_FORK_MATRIX") != "1" {
		t.Skip("set AGENT_SECRET_LIVE_FORK_MATRIX=1 to run maintainer live 1Password desktop SDK fork-removal matrix")
	}

	cfg := liveForkMatrixConfig{
		primaryAccount: envOrDefault("AGENT_SECRET_LIVE_PRIMARY_ACCOUNT", defaultLiveForkPrimaryAccount),
		primaryRef:     envOrDefault("AGENT_SECRET_LIVE_PRIMARY_REF", defaultLiveForkPrimaryRef),
		primaryItemRef: envOrDefault("AGENT_SECRET_LIVE_PRIMARY_ITEM_REF", defaultLiveForkPrimaryItemRef),
		primaryTextRef: envOrDefault("AGENT_SECRET_LIVE_PRIMARY_TEXT_REF", defaultLiveForkPrimaryTextRef),
		fixtureAccount: envOrDefault("AGENT_SECRET_LIVE_FIXTURE_ACCOUNT", defaultLiveForkFixtureAccount),
		fixtureRef:     envOrDefault("AGENT_SECRET_LIVE_FIXTURE_REF", defaultLiveForkFixtureRef),
	}

	for name, value := range map[string]string{
		"AGENT_SECRET_LIVE_PRIMARY_ACCOUNT":  cfg.primaryAccount,
		"AGENT_SECRET_LIVE_PRIMARY_REF":      cfg.primaryRef,
		"AGENT_SECRET_LIVE_PRIMARY_ITEM_REF": cfg.primaryItemRef,
		"AGENT_SECRET_LIVE_PRIMARY_TEXT_REF": cfg.primaryTextRef,
		"AGENT_SECRET_LIVE_FIXTURE_ACCOUNT":  cfg.fixtureAccount,
		"AGENT_SECRET_LIVE_FIXTURE_REF":      cfg.fixtureRef,
	} {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s must be non-empty", name)
		}
	}

	return cfg
}

func envOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func resolveLiveMatrixSecret(
	t *testing.T,
	ctx context.Context,
	pool *DesktopPool,
	ref string,
	account string,
) string {
	t.Helper()
	value, err := pool.Resolve(ctx, ref, account)
	if err != nil {
		t.Fatalf("resolve %s with account %s: %v", ref, account, err)
	}
	metadata := Secret{value: value}.Metadata()
	if metadata.Length == 0 || metadata.SHA256 == "" {
		t.Fatalf("resolved secret metadata is incomplete for %s with account %s: %+v", ref, account, metadata)
	}
	return value
}

func assertLiveMatrixMetadata(
	t *testing.T,
	metadata itemmetadata.Metadata,
	account string,
	ref itemmetadata.Ref,
) {
	t.Helper()
	if metadata.Account != account {
		t.Fatalf("metadata account = %q, want %q", metadata.Account, account)
	}
	if metadata.Vault != ref.Vault {
		t.Fatalf("metadata vault = %q, want %q", metadata.Vault, ref.Vault)
	}
	if metadata.Item != ref.Item {
		t.Fatalf("metadata item = %q, want %q", metadata.Item, ref.Item)
	}
	if metadata.Category == "" {
		t.Fatalf("metadata category is empty")
	}
	if len(metadata.Fields) == 0 {
		t.Fatalf("metadata fields are empty")
	}
}

func assertLiveMatrixField(t *testing.T, metadata itemmetadata.Metadata, wantRef string) {
	t.Helper()
	for _, field := range metadata.Fields {
		if field.Ref == wantRef {
			if field.Label == "" || field.Type == "" || field.Alias == "" {
				t.Fatalf("metadata field for %s is incomplete: %+v", wantRef, field)
			}
			return
		}
	}
	t.Fatalf("metadata did not include expected field ref %s", wantRef)
}
