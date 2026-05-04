package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func TestConnectWithPeerValidatorAcceptsTrustedDaemonPeer(t *testing.T) {
	t.Parallel()

	path, stop := startStatusDaemon(t)
	defer stop()

	client, err := ConnectWithPeerValidator(
		context.Background(),
		path,
		peertrust.NewDaemonValidator([]string{currentExecutableForControl(t)}),
	)
	if err != nil {
		t.Fatalf("ConnectWithPeerValidator returned error: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
}

func TestConnectWithPeerValidatorRejectsUntrustedDaemonBeforeExecPayload(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	trustedDaemon := writeDaemonExecutableAt(t, t.TempDir())

	client, err := ConnectWithPeerValidator(
		context.Background(),
		path,
		peertrust.NewDaemonValidator([]string{trustedDaemon}),
	)
	if err == nil {
		defer func() { _ = client.Close() }()
		t.Fatal("ConnectWithPeerValidator accepted untrusted daemon")
	}
	if !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		t.Fatalf("ConnectWithPeerValidator error = %v, want %v", err, peertrust.ErrUntrustedDaemon)
	}
}

func startStatusDaemon(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-status-daemon-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		done <- serveStatusPayload(conn)
	}()
	return path, func() {
		_ = listener.Close()
		defer func() { _ = os.RemoveAll(dir) }()
		if err := <-done; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("fake status daemon returned error: %v", err)
		}
	}
}

func serveStatusPayload(conn *net.UnixConn) error {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var env protocol.Envelope
	if err := decoder.Decode(&env); err != nil {
		return err
	}
	if env.Type != protocol.TypeDaemonStatus {
		return errors.New("expected daemon.status request")
	}
	resp, err := protocol.NewEnvelope(protocol.TypeOK, env.Correlation(), protocol.StatusPayload{PID: os.Getpid()})
	if err != nil {
		return err
	}
	return encoder.Encode(resp)
}

func currentExecutableForControl(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	return exe
}
