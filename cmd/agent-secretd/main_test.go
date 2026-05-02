package main

import "testing"

func TestDefaultApproverFlagValueIgnoresEnvironmentOverride(t *testing.T) {
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/fake-approver")

	if got := defaultApproverFlagValue(); got != "" {
		t.Fatalf("default approver flag value = %q, want empty", got)
	}
}

func TestNewResolverUsesDesktopResolverWithoutAccountOverride(t *testing.T) {
	t.Parallel()

	resolver := newResolver(" \t ")
	desktop, ok := resolver.(*desktopResolver)
	if !ok {
		t.Fatalf("resolver type = %T, want *desktopResolver", resolver)
	}
	if desktop.account != "" {
		t.Fatalf("account = %q, want resolver-level default account", desktop.account)
	}
}

func TestDesktopResolverEffectiveAccountUsesPerSecretOverride(t *testing.T) {
	t.Parallel()

	resolver, ok := newResolver("Fixture").(*desktopResolver)
	if !ok {
		t.Fatal("resolver is not a desktop resolver")
	}
	if account := resolver.effectiveAccount(" Preview "); account != "Preview" {
		t.Fatalf("account = %q, want Preview", account)
	}
	if account := resolver.effectiveAccount(" \t "); account != "Fixture" {
		t.Fatalf("account = %q, want Fixture", account)
	}
}
