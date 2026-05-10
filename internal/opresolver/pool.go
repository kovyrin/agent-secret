package opresolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
)

const DefaultDesktopPoolInitTimeout = 30 * time.Second

type DesktopResolverFactory func(context.Context, ClientOptions) (*ItemResolver, error)

type DesktopPoolOptions struct {
	IntegrationName    string
	IntegrationVersion string
	InitTimeout        time.Duration
	Factory            DesktopResolverFactory
}

type DesktopPool struct {
	mu                 sync.Mutex
	integrationName    string
	integrationVersion string
	initTimeout        time.Duration
	clients            map[string]*ItemResolver
	inits              map[string]*desktopPoolInit
	newDesktopResolver DesktopResolverFactory
}

type desktopPoolResult struct {
	resolver *ItemResolver
	err      error
}

type desktopPoolInit struct {
	done     chan struct{}
	resolver *ItemResolver
	err      error
}

func NewDesktopPool() *DesktopPool {
	return NewDesktopPoolWithOptions(DesktopPoolOptions{})
}

func NewDesktopPoolWithOptions(opts DesktopPoolOptions) *DesktopPool {
	initTimeout := opts.InitTimeout
	if initTimeout <= 0 {
		initTimeout = DefaultDesktopPoolInitTimeout
	}
	factory := opts.Factory
	if factory == nil {
		factory = NewDesktopResolver
	}
	return &DesktopPool{
		integrationName:    strings.TrimSpace(opts.IntegrationName),
		integrationVersion: strings.TrimSpace(opts.IntegrationVersion),
		initTimeout:        initTimeout,
		clients:            make(map[string]*ItemResolver),
		inits:              make(map[string]*desktopPoolInit),
		newDesktopResolver: factory,
	}
}

func (p *DesktopPool) Resolve(ctx context.Context, ref string, account string) (string, error) {
	account = strings.TrimSpace(account)
	resolver, err := p.client(ctx, account)
	if err != nil {
		return "", fmt.Errorf("create 1Password resolver: %w", err)
	}
	secret, err := resolver.ResolveSecret(ctx, ref)
	if err != nil {
		if shouldRefreshDesktopClient(err) {
			refreshed, refreshErr := p.resolveWithRefreshedClient(ctx, ref, account, resolver)
			if refreshErr == nil {
				return refreshed, nil
			}
			return "", fmt.Errorf("resolve secret: %w", staleClientRefreshError(err, refreshErr))
		}
		return "", fmt.Errorf("resolve secret: %w", err)
	}
	return secret.Value(), nil
}

func (p *DesktopPool) DescribeItem(
	ctx context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	account = strings.TrimSpace(account)
	resolver, err := p.client(ctx, account)
	if err != nil {
		return itemmetadata.Metadata{}, fmt.Errorf("create 1Password resolver: %w", err)
	}
	metadata, err := resolver.DescribeItem(ctx, ref, account)
	if err != nil {
		if shouldRefreshDesktopClient(err) {
			refreshed, refreshErr := p.describeItemWithRefreshedClient(ctx, ref, account, resolver)
			if refreshErr == nil {
				return refreshed, nil
			}
			return itemmetadata.Metadata{}, fmt.Errorf("describe item metadata: %w", staleClientRefreshError(err, refreshErr))
		}
		return itemmetadata.Metadata{}, fmt.Errorf("describe item metadata: %w", err)
	}
	return metadata, nil
}

func (p *DesktopPool) resolveWithRefreshedClient(
	ctx context.Context,
	ref string,
	account string,
	stale *ItemResolver,
) (string, error) {
	p.evictClient(account, stale)
	resolver, err := p.client(ctx, account)
	if err != nil {
		return "", err
	}
	secret, err := resolver.ResolveSecret(ctx, ref)
	if err != nil {
		return "", err
	}
	return secret.Value(), nil
}

func (p *DesktopPool) describeItemWithRefreshedClient(
	ctx context.Context,
	ref itemmetadata.Ref,
	account string,
	stale *ItemResolver,
) (itemmetadata.Metadata, error) {
	p.evictClient(account, stale)
	resolver, err := p.client(ctx, account)
	if err != nil {
		return itemmetadata.Metadata{}, err
	}
	metadata, err := resolver.DescribeItem(ctx, ref, account)
	if err != nil {
		return itemmetadata.Metadata{}, err
	}
	return metadata, nil
}

func staleClientRefreshError(originalErr error, refreshErr error) error {
	return errors.Join(originalErr, fmt.Errorf("refresh stale 1Password client: %w", refreshErr))
}

func shouldRefreshDesktopClient(err error) bool {
	if err == nil || errors.Is(err, ErrInvalidReference) {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "invalid client id") ||
		strings.Contains(message, "no vault matched the secret reference query")
}

func (p *DesktopPool) client(ctx context.Context, accountOverride string) (*ItemResolver, error) {
	account := strings.TrimSpace(accountOverride)
	resolver, init, owner := p.startClientInit(account)
	if resolver != nil {
		return resolver, nil
	}
	if !owner {
		return waitForDesktopPoolInit(ctx, init)
	}

	resolver, err := p.createClient(ctx, account)
	p.finishClientInit(account, init, resolver, err)
	return resolver, err
}

func (p *DesktopPool) startClientInit(account string) (*ItemResolver, *desktopPoolInit, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if resolver := p.clients[account]; resolver != nil {
		return resolver, nil, false
	}
	if init := p.inits[account]; init != nil {
		return nil, init, false
	}
	if p.inits == nil {
		p.inits = make(map[string]*desktopPoolInit)
	}
	init := &desktopPoolInit{done: make(chan struct{})}
	p.inits[account] = init
	return nil, init, true
}

func (p *DesktopPool) createClient(ctx context.Context, account string) (*ItemResolver, error) {
	initCtx, cancel := context.WithTimeout(ctx, p.initTimeout)
	defer cancel()
	results := make(chan desktopPoolResult, 1)
	factory := p.newDesktopResolver
	if factory == nil {
		factory = NewDesktopResolver
	}
	go func() {
		resolver, err := factory(initCtx, ClientOptions{
			Account:            account,
			IntegrationName:    p.integrationName,
			IntegrationVersion: p.integrationVersion,
		})
		results <- desktopPoolResult{resolver: resolver, err: err}
	}()

	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		return result.resolver, nil
	case <-initCtx.Done():
		return nil, fmt.Errorf(
			"create 1Password SDK client timed out after %s: unlock or restart 1Password and confirm SDK desktop integration is enabled: %w",
			p.initTimeout,
			initCtx.Err(),
		)
	}
}

func (p *DesktopPool) finishClientInit(account string, init *desktopPoolInit, resolver *ItemResolver, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err == nil {
		p.clients[account] = resolver
	}
	delete(p.inits, account)
	init.resolver = resolver
	init.err = err
	close(init.done)
}

func (p *DesktopPool) evictClient(account string, resolver *ItemResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients[account] == resolver {
		delete(p.clients, account)
	}
}

func waitForDesktopPoolInit(ctx context.Context, init *desktopPoolInit) (*ItemResolver, error) {
	select {
	case <-init.done:
		return init.resolver, init.err
	default:
	}

	select {
	case <-init.done:
		return init.resolver, init.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
