package gcpauth

import "context"

type OAuthLoginPromptRequest struct {
	AuthURL       string
	GoogleAccount string
	ExpectedEmail string
	Scopes        []string
}

type OAuthLoginPromptSession interface {
	Done() <-chan error
	Close() error
}

type OAuthLoginPrompter interface {
	StartOAuthLoginPrompt(ctx context.Context, req OAuthLoginPromptRequest) (OAuthLoginPromptSession, error)
}
