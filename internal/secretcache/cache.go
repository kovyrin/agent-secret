package secretcache

import (
	"sync"

	"github.com/kovyrin/agent-secret/internal/secretmem"
)

type SecretCache struct {
	mu     sync.Mutex
	values map[CacheKey]*secretmem.Value
}

type CacheKey struct {
	ScopeID              string
	Ref                  string
	Account              string
	Source               string
	BitwardenTokenAlias  string
	BitwardenAPIURL      string
	BitwardenIdentityURL string
}

func NewSecretCache() *SecretCache {
	return &SecretCache{values: make(map[CacheKey]*secretmem.Value)}
}

func (c *SecretCache) Put(key CacheKey, value string) error {
	lockedValue, err := secretmem.New(value)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if oldValue := c.values[key]; oldValue != nil {
		_ = oldValue.Destroy()
	}
	c.values[key] = lockedValue
	return nil
}

func (c *SecretCache) Get(key CacheKey) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.values[key]
	if !ok {
		return "", false
	}
	resolved, err := value.Reveal()
	if err != nil {
		return "", false
	}
	return resolved, true
}

func (c *SecretCache) ClearScope(scopeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.values {
		if key.ScopeID == scopeID {
			_ = c.values[key].Destroy()
			delete(c.values, key)
		}
	}
}

func (c *SecretCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, value := range c.values {
		_ = value.Destroy()
		delete(c.values, key)
	}
}
