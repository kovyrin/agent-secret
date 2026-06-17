package broker

import (
	"fmt"
	"path/filepath"

	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type SessionPeerAuthorizer interface {
	BindSessionPeer(peer peercred.Info, policy request.SessionBindingPolicy) (SessionPeerBinding, error)
	ValidateSessionPeer(binding SessionPeerBinding, peer peercred.Info) error
}

type SessionPeerBinding struct {
	CreatorPeer peercred.Info
	Anchor      peercred.ProcessIdentity
	Policy      request.SessionBindingPolicy
}

func (b SessionPeerBinding) Info() request.SessionBindingInfo {
	return request.SessionBindingInfo{
		Mode:          b.Policy.Mode,
		AncestorDepth: b.Policy.AncestorDepth,
		AncestorName:  b.Policy.AncestorName,
		BoundProcess:  processInfoFromIdentity(b.Anchor),
		CreatorProcess: request.SessionBindingProcess{
			PID:  b.CreatorPeer.PID,
			Name: processName(b.CreatorPeer.ExecutablePath),
			Path: b.CreatorPeer.ExecutablePath,
		},
	}
}

type SessionPeerMismatchError struct {
	Bound     request.SessionBindingProcess
	Requester request.SessionBindingProcess
	Reason    string
}

func (e *SessionPeerMismatchError) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = "requester ancestry does not include the approved session binding"
	}
	return fmt.Sprintf(
		"%s: %s; bound_process=%s pid=%d path=%q; requester=%s pid=%d path=%q; recreate the session from the shell or agent process tree that will run with-session, or use --bind-parent / --bind-ancestor N / --bind-ancestor-name NAME",
		ErrSessionPeerMismatch,
		reason,
		e.Bound.Name,
		e.Bound.PID,
		e.Bound.Path,
		e.Requester.Name,
		e.Requester.PID,
		e.Requester.Path,
	)
}

func (e *SessionPeerMismatchError) Unwrap() error {
	return ErrSessionPeerMismatch
}

type processTreeSessionPeerAuthorizer struct {
	processAncestry func(int) ([]peercred.ProcessIdentity, error)
}

func newProcessTreeSessionPeerAuthorizer() processTreeSessionPeerAuthorizer {
	return processTreeSessionPeerAuthorizer{processAncestry: peercred.ProcessAncestry}
}

func (a processTreeSessionPeerAuthorizer) BindSessionPeer(
	peer peercred.Info,
	policy request.SessionBindingPolicy,
) (SessionPeerBinding, error) {
	policy, err := request.NormalizeSessionBindingPolicy(policy)
	if err != nil {
		return SessionPeerBinding{}, err
	}
	ancestry, err := a.processAncestry(peer.PID)
	if err != nil {
		return SessionPeerBinding{}, fmt.Errorf("%w: inspect session creator process tree: %w", ErrSessionPeerMismatch, err)
	}
	anchor, policy, err := sessionPeerAnchor(peer, ancestry, policy)
	if err != nil {
		return SessionPeerBinding{}, err
	}
	return SessionPeerBinding{
		CreatorPeer: peer,
		Anchor:      anchor,
		Policy:      policy,
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
	if processAncestryContains(ancestry, binding.Anchor) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect session caller process tree: %w", ErrSessionPeerMismatch, err)
	}
	return &SessionPeerMismatchError{
		Bound:     processInfoFromIdentity(binding.Anchor),
		Requester: processInfoFromPeer(peer),
	}
}

func sessionPeerAnchor(
	peer peercred.Info,
	ancestry []peercred.ProcessIdentity,
	policy request.SessionBindingPolicy,
) (peercred.ProcessIdentity, request.SessionBindingPolicy, error) {
	if len(ancestry) == 0 || ancestry[0].PID != peer.PID {
		return peercred.ProcessIdentity{}, request.SessionBindingPolicy{}, fmt.Errorf("%w: session creator process tree does not start at pid %d", ErrSessionPeerMismatch, peer.PID)
	}
	switch policy.Mode {
	case request.SessionBindingModeAuto:
		anchor, err := automaticSessionPeerAnchor(peer, ancestry)
		return anchor, policy, err
	case request.SessionBindingModeAncestor:
		anchor, err := ancestorSessionPeerAnchor(peer, ancestry, policy.AncestorDepth)
		return anchor, policy, err
	case request.SessionBindingModeAncestorName:
		anchor, depth, err := ancestorNameSessionPeerAnchor(peer, ancestry, policy.AncestorName)
		policy.AncestorDepth = depth
		return anchor, policy, err
	default:
		return peercred.ProcessIdentity{}, request.SessionBindingPolicy{}, fmt.Errorf("%w: unknown binding mode %q", request.ErrInvalidSessionBind, policy.Mode)
	}
}

func automaticSessionPeerAnchor(peer peercred.Info, ancestry []peercred.ProcessIdentity) (peercred.ProcessIdentity, error) {
	for i := 1; i < len(ancestry); i++ {
		candidate := ancestry[i]
		if isEligibleSessionPeerAnchor(peer, candidate) {
			if next, ok := nextEligibleSessionPeerAnchor(peer, ancestry[i+1:]); ok &&
				isSameExecutableAncestor(candidate, next) {
				continue
			}
			return candidate, nil
		}
	}
	return peercred.ProcessIdentity{}, fmt.Errorf("%w: session creator has no stable requester parent", ErrSessionPeerMismatch)
}

func ancestorSessionPeerAnchor(
	peer peercred.Info,
	ancestry []peercred.ProcessIdentity,
	depth int,
) (peercred.ProcessIdentity, error) {
	if depth < 1 || depth >= len(ancestry) {
		return peercred.ProcessIdentity{}, fmt.Errorf(
			"%w: session creator does not have ancestor depth %d",
			ErrSessionPeerMismatch,
			depth,
		)
	}
	anchor := ancestry[depth]
	// Explicit binding means exactly the requested ancestor depth. Unlike auto
	// mode, it intentionally does not skip same-executable subshells.
	if !isEligibleSessionPeerAnchor(peer, anchor) {
		return peercred.ProcessIdentity{}, fmt.Errorf(
			"%w: ancestor depth %d is not an eligible same-user non-launchd binding target: %s pid=%d path=%q",
			ErrSessionPeerMismatch,
			depth,
			processName(anchor.ExecutablePath),
			anchor.PID,
			anchor.ExecutablePath,
		)
	}
	return anchor, nil
}

func ancestorNameSessionPeerAnchor(
	peer peercred.Info,
	ancestry []peercred.ProcessIdentity,
	name string,
) (peercred.ProcessIdentity, int, error) {
	var ineligible peercred.ProcessIdentity
	matchedIneligible := false
	for depth := 1; depth < len(ancestry); depth++ {
		anchor := ancestry[depth]
		if processName(anchor.ExecutablePath) != name {
			continue
		}
		if !isEligibleSessionPeerAnchor(peer, anchor) {
			if !matchedIneligible {
				ineligible = anchor
				matchedIneligible = true
			}
			continue
		}
		return anchor, depth, nil
	}
	if matchedIneligible {
		return peercred.ProcessIdentity{}, 0, fmt.Errorf(
			"%w: ancestor name %q matched only ineligible binding targets; nearest was %s pid=%d path=%q",
			ErrSessionPeerMismatch,
			name,
			processName(ineligible.ExecutablePath),
			ineligible.PID,
			ineligible.ExecutablePath,
		)
	}
	return peercred.ProcessIdentity{}, 0, fmt.Errorf("%w: session creator has no eligible ancestor named %q", ErrSessionPeerMismatch, name)
}

func isEligibleSessionPeerAnchor(peer peercred.Info, candidate peercred.ProcessIdentity) bool {
	if candidate.PID <= 1 || candidate.UID != peer.UID || candidate.GID != peer.GID || candidate.StartTime.IsZero() {
		return false
	}
	return filepath.Base(candidate.ExecutablePath) != "launchd"
}

func nextEligibleSessionPeerAnchor(
	peer peercred.Info,
	ancestry []peercred.ProcessIdentity,
) (peercred.ProcessIdentity, bool) {
	for _, candidate := range ancestry {
		if isEligibleSessionPeerAnchor(peer, candidate) {
			return candidate, true
		}
	}
	return peercred.ProcessIdentity{}, false
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

func processInfoFromIdentity(identity peercred.ProcessIdentity) request.SessionBindingProcess {
	return request.SessionBindingProcess{
		PID:       identity.PID,
		ParentPID: identity.ParentPID,
		Name:      processName(identity.ExecutablePath),
		Path:      identity.ExecutablePath,
	}
}

func processInfoFromPeer(peer peercred.Info) request.SessionBindingProcess {
	return request.SessionBindingProcess{
		PID:  peer.PID,
		Name: processName(peer.ExecutablePath),
		Path: peer.ExecutablePath,
	}
}

func processName(path string) string {
	if path == "" {
		return "unknown"
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return path
	}
	return name
}
