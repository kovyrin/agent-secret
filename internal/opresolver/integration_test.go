//go:build integration

package opresolver

import (
	"context"
	"os"
	"strings"
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

func TestLiveDesktopResolveTextFileReference(t *testing.T) {
	ref := os.Getenv("AGENT_SECRET_LIVE_TEXT_FILE_REF")
	account := os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT")
	if ref == "" {
		t.Skip("set AGENT_SECRET_LIVE_TEXT_FILE_REF to run live 1Password SDK text-file test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	resolver, err := NewDesktopResolver(ctx, ClientOptions{
		Account:            account,
		IntegrationName:    "Agent Secret Broker SDK Text File Test",
		IntegrationVersion: "dev",
	})
	if err != nil {
		t.Fatalf("create desktop resolver: %v", err)
	}

	secret, err := resolver.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve live text-file reference: %v", err)
	}

	value := secret.Value()
	if strings.ContainsRune(value, '\x00') {
		t.Fatal("resolved text-file reference contained a NUL byte; env delivery supports text only")
	}
	if !strings.Contains(value, "\n") {
		t.Fatal("resolved text-file reference was not multiline")
	}

	lineCount := strings.Count(value, "\n")
	if !strings.HasSuffix(value, "\n") {
		lineCount++
	}
	t.Logf(
		"resolved 1Password text-file reference metadata: length=%d lines=%d final_newline=%t",
		len(value),
		lineCount,
		strings.HasSuffix(value, "\n"),
	)
}
