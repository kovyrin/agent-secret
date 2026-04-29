//go:build integration

package opresolver

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveDesktopResolve(t *testing.T) {
	ref := os.Getenv("AGENT_SECRET_LIVE_REF")
	account := os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT")
	if ref == "" {
		t.Skip("set AGENT_SECRET_LIVE_REF to run live 1Password SDK test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resolver, err := NewDesktopResolver(ctx, ClientOptions{
		Account:            account,
		IntegrationName:    "Agent Secret Broker SDK Spike",
		IntegrationVersion: "dev",
	})
	if err != nil {
		t.Fatalf("create desktop resolver: %v", err)
	}

	secret, err := resolver.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve live reference: %v", err)
	}

	metadata := secret.Metadata()
	t.Logf("resolved 1Password reference metadata: length=%d sha256=%s", metadata.Length, metadata.SHA256)
}
