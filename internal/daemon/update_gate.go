package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
)

type updateAdmission struct {
	mu       sync.Mutex
	inFlight int
	draining bool
}

func (g *updateAdmission) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return false
	}
	g.inFlight++
	return true
}

func (g *updateAdmission) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inFlight--
}

func (g *updateAdmission) drain(idle func() bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining || g.inFlight != 0 || !idle() {
		return false
	}
	g.draining = true
	return true
}

func (s *Server) handleUpdateQuiesce(ctx context.Context, conn *net.UnixConn, encoder *json.Encoder, env protocol.Envelope) {
	if s.updaterValidator == nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeUntrustedClient, peertrust.ErrUntrustedClient)
		return
	}
	peer, err := s.peerInfo(conn)
	if err != nil || s.updaterValidator.ValidatePeer(peer) != nil {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeUntrustedClient, peertrust.ErrUntrustedClient)
		return
	}
	if !s.updateAdmission.drain(s.broker.IdleForUpdate) {
		_ = writeErrorEncoder(encoder, env.Correlation(), protocol.ErrorCodeUpdateBusy,
			errors.New("pending work or active sessions"))
		return
	}
	_ = writeOK(encoder, env.Correlation(), nil)
	s.Stop(ctx)
}
