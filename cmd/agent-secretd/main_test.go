package main

import "testing"

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
