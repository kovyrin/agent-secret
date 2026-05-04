package opresolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const DefaultDesktopPoolInitTimeout = 30 * time.Second

var ErrAccountRequired = errors.New("1Password account is required")

type DesktopResolverFactory func(context.Context, ClientOptions) (*Resolver, error)

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
	clients            map[string]*Resolver
	inits              map[string]*desktopPoolInit
	newDesktopResolver DesktopResolverFactory
}

type desktopPoolResult struct {
	resolver *Resolver
	err      error
}

type desktopPoolInit struct {
	done     chan struct{}
	resolver *Resolver
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
		clients:            make(map[string]*Resolver),
		inits:              make(map[string]*desktopPoolInit),
		newDesktopResolver: factory,
	}
}

func (p *DesktopPool) Resolve(ctx context.Context, ref string, account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", ErrAccountRequired
	}
	resolver, err := p.client(ctx, account)
	if err != nil {
		return "", fmt.Errorf("create 1Password resolver: %w", err)
	}
	secret, err := resolver.ResolveSecret(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve secret: %w", err)
	}
	return secret.Value(), nil
}

func (p *DesktopPool) client(ctx context.Context, accountOverride string) (*Resolver, error) {
	account := strings.TrimSpace(accountOverride)
	if account == "" {
		return nil, ErrAccountRequired
	}
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

func (p *DesktopPool) startClientInit(account string) (*Resolver, *desktopPoolInit, bool) {
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

func (p *DesktopPool) createClient(ctx context.Context, account string) (*Resolver, error) {
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

func (p *DesktopPool) finishClientInit(account string, init *desktopPoolInit, resolver *Resolver, err error) {
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

func waitForDesktopPoolInit(ctx context.Context, init *desktopPoolInit) (*Resolver, error) {
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
