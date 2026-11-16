package daemon

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

type roleValidator string

func (v roleValidator) ValidatePeer(info peercred.Info) error {
	if info.ExecutablePath == string(v) {
		return nil
	}
	return peertrust.ErrUntrustedClient
}

func TestUpdateControlIsSeparatedFromTheSecretClientRole(t *testing.T) {
	const cli = "/installed/agent-secret"
	const updater = "/installed/agent-secret-updater"
	for _, test := range []struct {
		name     string
		peer     string
		message  protocol.MessageType
		expected protocol.ErrorCode
	}{
		{"updater may ask an idle broker to retire", updater, protocol.TypeUpdateQuiesce, ""},
		{"CLI cannot invoke update control", cli, protocol.TypeUpdateQuiesce, protocol.ErrorCodeUntrustedClient},
		{"updater cannot request secrets", updater, protocol.TypeRequestExec, protocol.ErrorCodeUntrustedClient},
		{"updater cannot list sessions", updater, protocol.TypeSessionList, protocol.ErrorCodeUntrustedClient},
		{"updater cannot force stop", updater, protocol.TypeDaemonStop, protocol.ErrorCodeUntrustedClient},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewServer(ServerOptions{
				Broker: newTestBroker(t, daemonbroker.Options{
					Approver: &mockApprover{decision: approval.Decision{Approved: true}},
					Resolver: &mockResolver{}, Audit: &memoryAudit{},
				}),
				Validator:        staticPeerValidator{info: peercred.Info{ExecutablePath: test.peer}},
				ClientValidator:  roleValidator(cli),
				UpdaterValidator: roleValidator(updater),
			})
			if err != nil {
				t.Fatal(err)
			}
			serverConn, clientConn := unixsocket.Pair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.handleConn(context.Background(), serverConn)
			}()
			defer func() {
				_ = clientConn.Close()
				<-done
			}()
			msg, err := protocol.NewEnvelope(test.message, protocol.Correlation{RequestID: "request", Nonce: "nonce"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(clientConn).Encode(msg); err != nil {
				t.Fatal(err)
			}
			response := readRawEnvelope(t, json.NewDecoder(clientConn))
			if test.expected == "" {
				if response.Type != protocol.TypeOK {
					t.Fatalf("trusted updater received %v, want ok", response.Type)
				}
				return
			}
			payload, err := protocol.DecodePayload[protocol.ErrorPayload](response)
			if err != nil || response.Type != protocol.TypeError || payload.Code != test.expected {
				t.Fatalf("got %v/%v/%v, want %v", response.Type, payload.Code, err, test.expected)
			}
		})
	}
}

func TestInstallationAdmissionWaitsForWorkAndBlocksNewWork(t *testing.T) {
	var gate updateAdmission
	if !gate.enter() {
		t.Fatal("initial work refused")
	}
	if gate.drain(func() bool { return true }) {
		t.Fatal("installation admitted while a request is in progress")
	}
	gate.leave()
	if gate.drain(func() bool { return false }) {
		t.Fatal("installation admitted with protected broker state")
	}
	if !gate.drain(func() bool { return true }) || gate.enter() {
		t.Fatal("installation failed to exclude new work")
	}
}

func TestInstallationAdmissionRacesNewWork(t *testing.T) {
	for range 100 {
		var gate updateAdmission
		var count atomic.Int32
		var ready sync.WaitGroup
		start := make(chan struct{})
		ready.Go(func() {
			<-start
			if gate.enter() {
				count.Add(1)
			}
		})
		ready.Go(func() {
			<-start
			if gate.drain(func() bool { return true }) {
				count.Add(1)
			}
		})
		close(start)
		ready.Wait()
		if count.Load() != 1 {
			t.Fatal("work and installation admission are not exclusive")
		}
	}
}
