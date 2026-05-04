package approval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/trust"
)

type ProcessApproverLauncher struct {
	AppPath        string
	IdentityPolicy ApproverIdentityPolicy
}

func (l ProcessApproverLauncher) CheckHealth(ctx context.Context) error {
	executable, err := l.executablePath()
	if err != nil {
		return err
	}
	identity, err := l.identityPolicy().ValidateApproverExecutable(executable)
	if err != nil {
		return err
	}

	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	//nolint:gosec // G204: executable was canonicalized and validated by the approver identity policy above.
	cmd := exec.CommandContext(checkCtx, identity.ExecutablePath, "--health-check")
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("%w: open /dev/null: %w", ErrApproverLaunchFailed, err)
	}
	defer func() { _ = devNull.Close() }()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdin = devNull
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := checkCtx.Err(); ctxErr != nil {
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				return fmt.Errorf("%w: health check timed out: %w", ErrApproverLaunchFailed, ctxErr)
			}
			return fmt.Errorf("%w: health check canceled: %w", ErrApproverLaunchFailed, ctxErr)
		}
		return fmt.Errorf("%w: health check failed: %w", ErrApproverLaunchFailed, err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "Agent Secret: ok" {
		return fmt.Errorf("%w: unexpected health check response %q", ErrApproverLaunchFailed, got)
	}
	return nil
}

func (l ProcessApproverLauncher) Launch(ctx context.Context, socketPath string, _ ApprovalRequestPayload) (ExpectedApprover, error) {
	executable, err := l.executablePath()
	if err != nil {
		return ExpectedApprover{}, err
	}
	identity, err := l.identityPolicy().ValidateApproverExecutable(executable)
	if err != nil {
		return ExpectedApprover{}, err
	}
	executable = identity.ExecutablePath

	if err := ctx.Err(); err != nil {
		return ExpectedApprover{}, err
	}
	//nolint:gosec,noctx // G204: executable was canonicalized and validated above; CommandContext would kill a successfully launched approver when the approval job completes.
	cmd := exec.Command(executable, "--socket", socketPath)
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return ExpectedApprover{}, fmt.Errorf("%w: open /dev/null: %w", ErrApproverLaunchFailed, err)
	}
	defer func() { _ = devNull.Close() }()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := cmd.Start(); err != nil {
		return ExpectedApprover{}, fmt.Errorf("%w: %w", ErrApproverLaunchFailed, err)
	}
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return ExpectedApprover{}, ctx.Err()
	default:
	}
	expected := ExpectedApprover{
		PID:               cmd.Process.Pid,
		ExecutablePath:    executable,
		ExpectedTeamID:    identity.ExpectedTeamID,
		VerifySignature:   identity.VerifySignature,
		SignatureVerifier: trust.CodesignSignatureVerifier{},
	}
	exited := make(chan error, 1)
	expected.Exited = exited
	go func() {
		exited <- cmd.Wait()
		close(exited)
	}()
	return expected, nil
}

func (l ProcessApproverLauncher) executablePath() (string, error) {
	if l.AppPath == "" {
		return defaultApproverPath()
	}
	if filepath.Ext(l.AppPath) == ".app" {
		for _, candidate := range approverExecutablesInApp(l.AppPath) {
			if executableExists(candidate) {
				return candidate, nil
			}
		}
		return approverExecutablesInApp(l.AppPath)[0], nil
	}
	return l.AppPath, nil
}

func (l ProcessApproverLauncher) identityPolicy() ApproverIdentityPolicy {
	if l.IdentityPolicy != nil {
		return l.IdentityPolicy
	}
	return DefaultApproverIdentityPolicy()
}
