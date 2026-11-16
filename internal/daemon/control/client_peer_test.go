package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/messageauth"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func TestConnectWithPeerValidatorAcceptsTrustedDaemonPeer(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("request attestation requires macOS")
	}
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

func TestBeginMessageAuthRejectsMissingPort(t *testing.T) {
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	response, err := protocol.NewEnvelope(protocol.TypeOK, protocol.Correlation{}, protocol.AuthHelloPayload{})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(serverConn).Encode(response); err != nil {
		t.Fatal(err)
	}
	if err := NewClient(clientConn).beginMessageAuth(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "no port") {
		t.Fatalf("missing authentication port error = %v", err)
	}
}

func TestBeginMessageAuthHonorsCanceledContext(t *testing.T) {
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewClient(clientConn).beginMessageAuth(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authentication error = %v, want context.Canceled", err)
	}
}

func TestBeginMessageAuthRejectsDaemonErrorAndUnexpectedReply(t *testing.T) {
	for _, tc := range []struct {
		name       string
		response   protocol.Envelope
		wantCode   protocol.ErrorCode
		wantPhrase string
	}{
		{
			name: "daemon rejects identity",
			response: protocol.Envelope{
				Version: protocol.ProtocolVersion,
				Type:    protocol.TypeError,
				Payload: json.RawMessage(`{"code":"peer_rejected","message":"sender mismatch"}`),
			},
			wantCode: protocol.ErrorCodePeerRejected,
		},
		{
			name: "unexpected reply",
			response: protocol.Envelope{
				Version: protocol.ProtocolVersion,
				Type:    protocol.TypeDaemonStatus,
			},
			wantPhrase: "rejected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := unixsocket.Pair(t)
			defer func() { _ = serverConn.Close() }()
			defer func() { _ = clientConn.Close() }()
			if err := json.NewEncoder(serverConn).Encode(tc.response); err != nil {
				t.Fatal(err)
			}
			err := NewClient(clientConn).beginMessageAuth(context.Background())
			if tc.wantCode != "" && !IsProtocolError(err, tc.wantCode) {
				t.Fatalf("daemon rejection = %v, want code %s", err, tc.wantCode)
			}
			if tc.wantPhrase != "" && (err == nil || !strings.Contains(err.Error(), tc.wantPhrase)) {
				t.Fatalf("unexpected reply error = %v, want %q", err, tc.wantPhrase)
			}
		})
	}
}

func TestClientDoesNotWriteRequestWhenAttestationFails(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("request attestation requires macOS")
	}
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	client := NewClient(clientConn)
	client.authPort = "com.kovyrin.agentsecret.auth.nonexistent"
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "send request attestation") {
		t.Fatalf("Status with missing attestation port = %v", err)
	}
	if err := serverConn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var byteBuffer [1]byte
	if _, err := serverConn.Read(byteBuffer[:]); err == nil {
		t.Fatal("request was written without an attestation")
	}
}

func TestValidateDaemonPeerAllowsNilValidator(t *testing.T) {
	t.Parallel()

	daemonConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = daemonConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	if err := validateDaemonPeer(clientConn, nil); err != nil {
		t.Fatalf("validateDaemonPeer returned error: %v", err)
	}
}

func TestValidateDaemonPeerInspectsSocketPairPeer(t *testing.T) {
	t.Parallel()

	daemonConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = daemonConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	validator := &recordingDaemonPeerValidator{}
	if err := validateDaemonPeer(clientConn, validator); err != nil {
		t.Fatalf("validateDaemonPeer returned error: %v", err)
	}
	if !validator.called {
		t.Fatal("validator was not called")
	}
	if validator.info.UID != os.Getuid() {
		t.Fatalf("daemon peer uid = %d, want %d", validator.info.UID, os.Getuid())
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

type recordingDaemonPeerValidator struct {
	called bool
	info   peercred.Info
}

func (v *recordingDaemonPeerValidator) ValidateDaemonPeer(info peercred.Info) error {
	v.called = true
	v.info = info
	return nil
}

func serveStatusPayload(conn *net.UnixConn) error {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var env protocol.Envelope
	if err := decoder.Decode(&env); err != nil {
		return err
	}
	if env.Type != protocol.TypeAuthHello {
		return errors.New("expected auth.hello request")
	}
	port, err := messageauth.NewPort()
	if err != nil {
		return err
	}
	defer port.Close()
	response, err := protocol.NewEnvelope(protocol.TypeOK, env.Correlation(), protocol.AuthHelloPayload{Port: port.Name()})
	if err != nil {
		return err
	}
	if err := encoder.Encode(response); err != nil {
		return err
	}
	if err := decoder.Decode(&env); err != nil {
		return err
	}
	if env.Type != protocol.TypeDaemonStatus {
		return errors.New("expected daemon.status request")
	}
	frame, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if _, err := port.Receive(frame, 5*time.Second); err != nil {
		return err
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
