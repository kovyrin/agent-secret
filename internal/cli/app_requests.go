package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
)

func (a App) ensureBackgroundHelper(ctx context.Context, manager daemonManager) error {
	result, err := manager.Repair(ctx)
	if err != nil {
		return err
	}
	if result.Status == control.RepairStatusRefreshed {
		a.stderrf("agent-secret: Activating Agent Secret local service...\n")
	}
	return nil
}

func backgroundHelperError(err error) string {
	if errors.Is(err, control.ErrUnexpectedHelper) {
		return "Agent Secret found an unexpected local service and refused to send secrets to it.\n" +
			"Details: " + err.Error() + "\n" +
			"Run `agent-secret install-cli --force` from the installed Agent Secret app to reactivate the local service."
	}
	return fmt.Sprintf("activate Agent Secret local service: %v", err)
}

func requestDaemonPayload[T any](
	ctx context.Context,
	manager daemonManager,
	send func(daemonClient) (T, error),
) (daemonClient, T, error) {
	var zero T
	client, err := manager.Connect(ctx)
	if err != nil {
		return nil, zero, fmt.Errorf("connect background helper: %w", err)
	}
	payload, err := send(client)
	if err == nil {
		return client, payload, nil
	}
	if !control.IsProtocolError(err, protocol.ErrorCodeDaemonStopped) {
		_ = client.Close()
		return nil, zero, fmt.Errorf("request rejected: %w", err)
	}
	_ = client.Close()

	if err := manager.EnsureRunning(ctx); err != nil {
		return nil, zero, fmt.Errorf("refresh background helper after upgrade: %w", err)
	}
	client, err = manager.Connect(ctx)
	if err != nil {
		return nil, zero, fmt.Errorf("connect background helper after upgrade: %w", err)
	}
	payload, err = send(client)
	if err != nil {
		_ = client.Close()
		return nil, zero, fmt.Errorf("request rejected: %w", err)
	}
	return client, payload, nil
}
