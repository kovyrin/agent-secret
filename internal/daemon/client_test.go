package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/request"
)

func TestConnectAcceptsTrustedDaemonPeer(t *testing.T) {
	t.Parallel()

	path, stop := startRawServerWithOptions(t, ServerOptions{
		Broker: newTestBroker(t, BrokerOptions{
			Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
			Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
			Audit:    &memoryAudit{},
		}),
		Validator: allowPeerValidator{},
	})
	defer stop()

	client, err := ConnectWithPeerValidator(
		context.Background(),
		path,
		NewTrustedDaemonValidator([]string{currentExecutable(t)}),
	)
	if err != nil {
		t.Fatalf("ConnectWithPeerValidator returned error: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Status(context.Background()); err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
}

func TestConnectRejectsUntrustedDaemonBeforeExecPayload(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	trustedDaemon := writeExecutableAt(t, t.TempDir(), "agent-secretd")

	client, err := ConnectWithPeerValidator(
		context.Background(),
		path,
		NewTrustedDaemonValidator([]string{trustedDaemon}),
	)
	if err == nil {
		defer func() { _ = client.Close() }()
		payload, requestErr := client.RequestExec(
			context.Background(),
			"req_1",
			"nonce_1",
			testExecRequest(t, []request.SecretSpec{{Alias: "TOKEN", Ref: "op://Example/Item/token"}}),
		)
		if requestErr == nil {
			t.Fatalf("accepted exec payload from untrusted daemon: %+v", payload.Env)
		}
		t.Fatalf("ConnectWithPeerValidator accepted untrusted daemon; request error = %v", requestErr)
	}
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("ConnectWithPeerValidator error = %v, want %v", err, ErrUntrustedDaemon)
	}
}

func TestManagerStatusRejectsUntrustedDaemonPeer(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	manager := Manager{
		SocketPath: path,
		DaemonPath: writeExecutableAt(t, t.TempDir(), "agent-secretd"),
	}

	_, err := manager.Status(context.Background())
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("Status error = %v, want %v", err, ErrUntrustedDaemon)
	}
}

func TestTrustedDaemonPathsForAppUseBundleExecutable(t *testing.T) {
	t.Parallel()

	appPath := filepath.Join(t.TempDir(), "AgentSecretDaemon.app")
	executablePath := filepath.Join(appPath, "Contents", "MacOS", "Agent Secret")
	if err := os.MkdirAll(filepath.Dir(executablePath), 0o750); err != nil {
		t.Fatalf("mkdir bundle executable dir: %v", err)
	}
	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon path tests need executable fixtures.
		t.Fatalf("write executable: %v", err)
	}
	info := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Agent Secret</string>
</dict>
</plist>
`
	if err := os.WriteFile(filepath.Join(appPath, "Contents", "Info.plist"), []byte(info), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}

	got := trustedDaemonPathsForPath(appPath)
	if len(got) != 1 || got[0] != executablePath {
		t.Fatalf("trusted daemon paths = %v, want [%s]", got, executablePath)
	}
}

func startFakeExecDaemon(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-fake-daemon-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serveFakeExecPayload(conn)
	}()
	return path, func() {
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
}

func serveFakeExecPayload(conn *net.UnixConn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var env Envelope
	if err := decoder.Decode(&env); err != nil {
		return
	}
	resp, err := NewEnvelope(TypeOK, env.RequestID, env.Nonce, ExecResponsePayload{
		Env:           map[string]string{"TOKEN": "attacker-controlled"},
		SecretAliases: []string{"TOKEN"},
	})
	if err != nil {
		return
	}
	if err := encoder.Encode(resp); err != nil {
		return
	}
}
