package approval

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/kovyrin/agent-secret/internal/gcpauth"
)

type GCPOAuthLoginPromptLauncher struct {
	AppLauncher ProcessApproverLauncher
}

func (l GCPOAuthLoginPromptLauncher) StartOAuthLoginPrompt(
	ctx context.Context,
	req gcpauth.OAuthLoginPromptRequest,
) (gcpauth.OAuthLoginPromptSession, error) {
	authURL := strings.TrimSpace(req.AuthURL)
	if authURL == "" {
		return nil, fmt.Errorf("%w: empty GCP OAuth URL", ErrApproverLaunchFailed)
	}
	if _, err := url.ParseRequestURI(authURL); err != nil {
		return nil, fmt.Errorf("%w: invalid GCP OAuth URL: %w", ErrApproverLaunchFailed, err)
	}

	launcher := l.AppLauncher
	identity, err := launcher.validatedExecutableIdentity()
	if err != nil {
		return nil, err
	}
	executable := identity.ExecutablePath

	args := []string{
		"--gcp-oauth-login",
		"--url", authURL,
		"--google-account", req.GoogleAccount,
	}
	if req.ExpectedEmail != "" {
		args = append(args, "--expected-email", req.ExpectedEmail)
	}
	for _, scope := range req.Scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			args = append(args, "--scope", scope)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	//nolint:gosec,noctx // G204: executable was canonicalized and validated above; OAuth URL is daemon-generated.
	cmd := exec.Command(executable, args...)
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open /dev/null: %w", ErrApproverLaunchFailed, err)
	}
	defer func() { _ = devNull.Close() }()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApproverLaunchFailed, err)
	}
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, ctx.Err()
	default:
	}

	done := make(chan error, 1)
	session := &processOAuthLoginPromptSession{
		process: cmd.Process,
		done:    done,
	}
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	return session, nil
}

type processOAuthLoginPromptSession struct {
	process *os.Process
	done    chan error
}

func (s *processOAuthLoginPromptSession) Done() <-chan error {
	return s.done
}

func (s *processOAuthLoginPromptSession) Close() error {
	if s.process == nil {
		return nil
	}
	select {
	case err := <-s.done:
		return err
	default:
	}
	if err := s.process.Kill(); err != nil {
		return err
	}
	select {
	case err := <-s.done:
		return err
	default:
		return nil
	}
}
