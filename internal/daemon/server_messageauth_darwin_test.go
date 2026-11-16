//go:build darwin

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/messageauth"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func TestAuthenticatedServerBindsExactFrame(t *testing.T) {
	if os.Getenv("AGENT_SECRET_TEST_MACOS_PEER_IDENTITY") != "1" {
		t.Skip("set AGENT_SECRET_TEST_MACOS_PEER_IDENTITY=1 for macOS socket credential integration")
	}
	server, err := NewServer(ServerOptions{
		Broker: newTestBroker(t, daemonbroker.Options{
			Approver: &mockApprover{decision: approval.Decision{Approved: true}},
			Resolver: &mockResolver{},
			Audit:    &memoryAudit{},
		}),
		Validator:       allowPeerValidator{},
		ClientValidator: trustedCurrentClientValidator(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	server.acceptPeer(serverConn)
	go server.handleConn(context.Background(), serverConn, true)
	reader := bufio.NewReader(clientConn)
	if err := json.NewEncoder(clientConn).Encode(protocol.Envelope{Version: 1, Type: protocol.TypeAuthHello}); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeOK {
		t.Fatalf("auth hello response: %+v, %v", response, err)
	}
	auth, err := protocol.DecodeRequiredPayload[protocol.AuthHelloPayload](response)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte(`{"version":1,"type":"daemon.status"}`)
	if err := messageauth.Send(auth.Port, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(append(frame, '\n')); err != nil {
		t.Fatal(err)
	}
	response, err = protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeOK {
		t.Fatalf("attested status response: %+v, %v", response, err)
	}
	if err := messageauth.Send(auth.Port, frame); err != nil {
		t.Fatal(err)
	}
	forged := []byte(`{"version":1,"type":"request.exec"}`)
	if _, err := clientConn.Write(append(forged, '\n')); err != nil {
		t.Fatal(err)
	}
	response, err = protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeError {
		t.Fatalf("mismatched frame response: %+v, %v", response, err)
	}
	payload, err := protocol.DecodeRequiredPayload[protocol.ErrorPayload](response)
	if err != nil || payload.Code != protocol.ErrorCodePeerRejected {
		t.Fatalf("mismatched frame error: %+v, %v", payload, err)
	}
}

func TestAuthenticatedServerRejectsRequestBeforeHandshake(t *testing.T) {
	if os.Getenv("AGENT_SECRET_TEST_MACOS_PEER_IDENTITY") != "1" {
		t.Skip("set AGENT_SECRET_TEST_MACOS_PEER_IDENTITY=1 for macOS socket credential integration")
	}
	server, err := NewServer(ServerOptions{
		Broker:          newTestBroker(t, daemonbroker.Options{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:       allowPeerValidator{},
		ClientValidator: trustedCurrentClientValidator(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	server.acceptPeer(serverConn)
	go server.handleConn(context.Background(), serverConn, true)
	reader := bufio.NewReader(clientConn)
	if err := json.NewEncoder(clientConn).Encode(protocol.Envelope{Version: 1, Type: protocol.TypeHelperHello}); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeOK {
		t.Fatalf("legacy inspection hello: %+v, %v", response, err)
	}
	if err := json.NewEncoder(clientConn).Encode(protocol.Envelope{Version: 1, Type: protocol.TypeRequestExec}); err != nil {
		t.Fatal(err)
	}
	response, err = protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeError {
		t.Fatalf("unauthenticated exec response: %+v, %v", response, err)
	}
	payload, err := protocol.DecodeRequiredPayload[protocol.ErrorPayload](response)
	if err != nil || payload.Code != protocol.ErrorCodePeerRejected {
		t.Fatalf("unauthenticated exec error: %+v, %v", payload, err)
	}
}

func TestAuthenticatedServerRejectsForeignMachSender(t *testing.T) {
	if os.Getenv("AGENT_SECRET_TEST_MACOS_PEER_IDENTITY") != "1" {
		t.Skip("set AGENT_SECRET_TEST_MACOS_PEER_IDENTITY=1 for macOS socket credential integration")
	}
	server, err := NewServer(ServerOptions{
		Broker:          newTestBroker(t, daemonbroker.Options{Approver: &mockApprover{}, Resolver: &mockResolver{}, Audit: &memoryAudit{}}),
		Validator:       allowPeerValidator{},
		ClientValidator: trustedCurrentClientValidator(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := unixsocket.Pair(t)
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()
	server.acceptPeer(serverConn)
	go server.handleConn(context.Background(), serverConn, true)
	reader := bufio.NewReader(clientConn)
	if err := json.NewEncoder(clientConn).Encode(protocol.Envelope{Version: 1, Type: protocol.TypeAuthHello}); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeOK {
		t.Fatalf("auth hello response: %+v, %v", response, err)
	}
	auth, err := protocol.DecodeRequiredPayload[protocol.AuthHelloPayload](response)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestForeignMachSenderHelper$") //nolint:gosec // Test re-executes its own binary.
	cmd.Env = append(os.Environ(), "AGENT_SECRET_FOREIGN_AUTH_PORT="+auth.Port)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreign sender: %v, output: %s", err, output)
	}
	frame := []byte(`{"version":1,"type":"request.exec"}`)
	if _, err := clientConn.Write(append(frame, '\n')); err != nil {
		t.Fatal(err)
	}
	response, err = protocol.ReadEnvelopeFrame(reader, protocol.DefaultMaxProtocolFrameBytes)
	if err != nil || response.Type != protocol.TypeError {
		t.Fatalf("foreign sender response: %+v, %v", response, err)
	}
	payload, err := protocol.DecodeRequiredPayload[protocol.ErrorPayload](response)
	if err != nil || payload.Code != protocol.ErrorCodePeerRejected {
		t.Fatalf("foreign sender error: %+v, %v", payload, err)
	}
}

func TestForeignMachSenderHelper(t *testing.T) {
	port := os.Getenv("AGENT_SECRET_FOREIGN_AUTH_PORT")
	if port == "" {
		return
	}
	if err := messageauth.Send(port, []byte(`{"version":1,"type":"request.exec"}`)); err != nil {
		t.Fatal(err)
	}
}
