package cli

import (
	"context"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
)

func requestDaemonPayload[T any](
	ctx context.Context,
	manager daemonManager,
	send func(daemonClient) (T, error),
) (daemonClient, T, error) {
	var zero T
	client, err := manager.Connect(ctx)
	if err != nil {
		return nil, zero, fmt.Errorf("connect daemon: %w", err)
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
		return nil, zero, fmt.Errorf("start daemon after upgrade: %w", err)
	}
	client, err = manager.Connect(ctx)
	if err != nil {
		return nil, zero, fmt.Errorf("connect daemon after upgrade: %w", err)
	}
	payload, err = send(client)
	if err != nil {
		_ = client.Close()
		return nil, zero, fmt.Errorf("request rejected: %w", err)
	}
	return client, payload, nil
}
