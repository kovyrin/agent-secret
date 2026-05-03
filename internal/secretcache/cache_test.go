package secretcache

import "testing"

func TestSecretCacheClearScope(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope_1", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put scope_1 returned error: %v", err)
	}
	if err := cache.Put("scope_2", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put scope_2 returned error: %v", err)
	}
	cache.ClearScope("scope_1")

	if _, ok := cache.Get("scope_1", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_1 value survived ClearScope")
	}
	if value, ok := cache.Get("scope_2", "op://Example/Item/token", ""); !ok || value != "second" {
		t.Fatalf("scope_2 value = %q, %v; want second, true", value, ok)
	}
}

func TestSecretCacheSeparatesSameRefAcrossAccounts(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope", "op://Example/Item/token", "Personal", "personal"); err != nil {
		t.Fatalf("Put Personal returned error: %v", err)
	}
	if err := cache.Put("scope", "op://Example/Item/token", "Work", "work"); err != nil {
		t.Fatalf("Put Work returned error: %v", err)
	}

	if value, ok := cache.Get("scope", "op://Example/Item/token", "Personal"); !ok || value != "personal" {
		t.Fatalf("personal value = %q, %v; want personal, true", value, ok)
	}
	if value, ok := cache.Get("scope", "op://Example/Item/token", "Work"); !ok || value != "work" {
		t.Fatalf("work value = %q, %v; want work, true", value, ok)
	}
}

func TestSecretCacheReplacesValues(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put first returned error: %v", err)
	}
	if err := cache.Put("scope", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put second returned error: %v", err)
	}

	if value, ok := cache.Get("scope", "op://Example/Item/token", ""); !ok || value != "second" {
		t.Fatalf("value = %q, %v; want second, true", value, ok)
	}
}

func TestSecretCacheClearRemovesAllValues(t *testing.T) {
	t.Parallel()

	cache := NewSecretCache()
	if err := cache.Put("scope_1", "op://Example/Item/token", "", "first"); err != nil {
		t.Fatalf("Put scope_1 returned error: %v", err)
	}
	if err := cache.Put("scope_2", "op://Example/Item/token", "", "second"); err != nil {
		t.Fatalf("Put scope_2 returned error: %v", err)
	}
	cache.Clear()

	if _, ok := cache.Get("scope_1", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_1 value survived Clear")
	}
	if _, ok := cache.Get("scope_2", "op://Example/Item/token", ""); ok {
		t.Fatal("scope_2 value survived Clear")
	}
}
