package broker

import (
	"fmt"
	"path/filepath"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

type SessionPeerAuthorizer interface {
	BindSessionPeer(peer peercred.Info) (SessionPeerBinding, error)
	ValidateSessionPeer(binding SessionPeerBinding, peer peercred.Info) error
}

type SessionPeerBinding struct {
	CreatorPeer peercred.Info
	Anchor      peercred.ProcessIdentity
}

type processTreeSessionPeerAuthorizer struct {
	processAncestry func(int) ([]peercred.ProcessIdentity, error)
}

func newProcessTreeSessionPeerAuthorizer() processTreeSessionPeerAuthorizer {
	return processTreeSessionPeerAuthorizer{processAncestry: peercred.ProcessAncestry}
}

func (a processTreeSessionPeerAuthorizer) BindSessionPeer(peer peercred.Info) (SessionPeerBinding, error) {
	ancestry, err := a.processAncestry(peer.PID)
	if err != nil {
		return SessionPeerBinding{}, fmt.Errorf("%w: inspect session creator process tree: %w", ErrSessionPeerMismatch, err)
	}
	anchor, err := sessionPeerAnchor(peer, ancestry)
	if err != nil {
		return SessionPeerBinding{}, err
	}
	return SessionPeerBinding{
		CreatorPeer: peer,
		Anchor:      anchor,
	}, nil
}

func (a processTreeSessionPeerAuthorizer) ValidateSessionPeer(
	binding SessionPeerBinding,
	peer peercred.Info,
) error {
	if binding.Anchor.PID <= 0 || binding.Anchor.StartTime.IsZero() {
		return fmt.Errorf("%w: session is missing requester process binding", ErrSessionPeerMismatch)
	}
	ancestry, err := a.processAncestry(peer.PID)
	if err != nil {
		return fmt.Errorf("%w: inspect session caller process tree: %w", ErrSessionPeerMismatch, err)
	}
	if processAncestryContains(ancestry, binding.Anchor) {
		return nil
	}
	return fmt.Errorf(
		"%w: caller pid %d is not in the approved requester process tree rooted at pid %d",
		ErrSessionPeerMismatch,
		peer.PID,
		binding.Anchor.PID,
	)
}

func sessionPeerAnchor(peer peercred.Info, ancestry []peercred.ProcessIdentity) (peercred.ProcessIdentity, error) {
	if len(ancestry) == 0 || ancestry[0].PID != peer.PID {
		return peercred.ProcessIdentity{}, fmt.Errorf("%w: session creator process tree does not start at pid %d", ErrSessionPeerMismatch, peer.PID)
	}
	for i, candidate := range ancestry[1:] {
		if isEligibleSessionPeerAnchor(peer, candidate) {
			if i+2 < len(ancestry) && isSameExecutableAncestor(candidate, ancestry[i+2]) {
				continue
			}
			return candidate, nil
		}
	}
	return peercred.ProcessIdentity{}, fmt.Errorf("%w: session creator has no stable requester parent", ErrSessionPeerMismatch)
}

func isEligibleSessionPeerAnchor(peer peercred.Info, candidate peercred.ProcessIdentity) bool {
	if candidate.PID <= 1 || candidate.UID != peer.UID || candidate.GID != peer.GID || candidate.StartTime.IsZero() {
		return false
	}
	return filepath.Base(candidate.ExecutablePath) != "launchd"
}

func isSameExecutableAncestor(candidate peercred.ProcessIdentity, ancestor peercred.ProcessIdentity) bool {
	return candidate.UID == ancestor.UID &&
		candidate.GID == ancestor.GID &&
		candidate.ExecutablePath != "" &&
		candidate.ExecutablePath == ancestor.ExecutablePath
}

func processAncestryContains(ancestry []peercred.ProcessIdentity, anchor peercred.ProcessIdentity) bool {
	for _, candidate := range ancestry {
		if sameProcessIdentity(candidate, anchor) {
			return true
		}
	}
	return false
}

func sameProcessIdentity(a peercred.ProcessIdentity, b peercred.ProcessIdentity) bool {
	return a.PID == b.PID &&
		a.UID == b.UID &&
		a.GID == b.GID &&
		a.StartTime.Equal(b.StartTime) &&
		a.ExecutablePath == b.ExecutablePath
}
