package broker

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestProcessTreeSessionPeerAuthorizerAllowsRequesterTreeSiblings(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(1002)
	requester := testProcessIdentity(500, 1, "/bin/zsh")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, requester.PID, creator.ExecutablePath),
			requester,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
		caller.PID: {
			testProcessIdentity(caller.PID, requester.PID, caller.ExecutablePath),
			requester,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if binding.Anchor.PID != requester.PID {
		t.Fatalf("binding anchor pid = %d, want %d", binding.Anchor.PID, requester.PID)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); err != nil {
		t.Fatalf("ValidateSessionPeer returned error for requester tree sibling: %v", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerSkipsSameExecutableSubshellAnchor(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(1002)
	subShell := testProcessIdentity(501, 500, "/bin/bash")
	taskShell := testProcessIdentity(500, 1, "/bin/bash")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, subShell.PID, creator.ExecutablePath),
			subShell,
			taskShell,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
		caller.PID: {
			testProcessIdentity(caller.PID, taskShell.PID, caller.ExecutablePath),
			taskShell,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if binding.Anchor.PID != taskShell.PID {
		t.Fatalf("binding anchor pid = %d, want task shell pid %d", binding.Anchor.PID, taskShell.PID)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); err != nil {
		t.Fatalf("ValidateSessionPeer returned error for task shell sibling: %v", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerSkipsSameExecutableSubshellAcrossIneligibleAncestor(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(1002)
	subShell := testProcessIdentity(501, 700, "/bin/bash")
	ineligibleDaemon := testProcessIdentity(700, 500, "/usr/libexec/example-daemon")
	ineligibleDaemon.UID = 0
	ineligibleDaemon.GID = 0
	taskShell := testProcessIdentity(500, 1, "/bin/bash")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, subShell.PID, creator.ExecutablePath),
			subShell,
			ineligibleDaemon,
			taskShell,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
		caller.PID: {
			testProcessIdentity(caller.PID, taskShell.PID, caller.ExecutablePath),
			taskShell,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if binding.Anchor.PID != taskShell.PID {
		t.Fatalf("binding anchor pid = %d, want task shell pid %d", binding.Anchor.PID, taskShell.PID)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); err != nil {
		t.Fatalf("ValidateSessionPeer returned error for task shell sibling: %v", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerBindsExplicitParent(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	subShell := testProcessIdentity(501, 500, "/bin/bash")
	taskShell := testProcessIdentity(500, 1, "/bin/bash")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, subShell.PID, creator.ExecutablePath),
			subShell,
			taskShell,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}
	policy, err := request.NewSessionAncestorBinding(1)
	if err != nil {
		t.Fatalf("NewSessionAncestorBinding returned error: %v", err)
	}

	binding, err := authorizer.BindSessionPeer(creator, policy)
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if binding.Anchor.PID != subShell.PID {
		t.Fatalf("binding anchor pid = %d, want explicit parent pid %d", binding.Anchor.PID, subShell.PID)
	}
	if binding.Policy != policy {
		t.Fatalf("binding policy = %+v, want %+v", binding.Policy, policy)
	}
}

func TestProcessTreeSessionPeerAuthorizerBindsExplicitAncestor(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	subShell := testProcessIdentity(501, 500, "/bin/zsh")
	agent := testProcessIdentity(500, 400, "/Applications/Codex.app/Contents/MacOS/Codex")
	terminal := testProcessIdentity(400, 1, "/Applications/iTerm.app/Contents/MacOS/iTerm2")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, subShell.PID, creator.ExecutablePath),
			subShell,
			agent,
			terminal,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}
	policy, err := request.NewSessionAncestorBinding(2)
	if err != nil {
		t.Fatalf("NewSessionAncestorBinding returned error: %v", err)
	}

	binding, err := authorizer.BindSessionPeer(creator, policy)
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if binding.Anchor.PID != agent.PID {
		t.Fatalf("binding anchor pid = %d, want explicit ancestor pid %d", binding.Anchor.PID, agent.PID)
	}
	info := binding.Info()
	if info.Mode != request.SessionBindingModeAncestor ||
		info.AncestorDepth != 2 ||
		info.BoundProcess.PID != agent.PID ||
		info.BoundProcess.Name != "Codex" ||
		info.CreatorProcess.PID != creator.PID {
		t.Fatalf("binding info = %+v", info)
	}
}

func TestProcessTreeSessionPeerAuthorizerRejectsIneligibleExplicitAncestor(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	rootParent := testProcessIdentity(500, 1, "/bin/zsh")
	rootParent.UID = 0
	rootParent.GID = 0
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, rootParent.PID, creator.ExecutablePath),
			rootParent,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	})}
	policy, err := request.NewSessionAncestorBinding(1)
	if err != nil {
		t.Fatalf("NewSessionAncestorBinding returned error: %v", err)
	}

	if _, err := authorizer.BindSessionPeer(creator, policy); !errors.Is(err, ErrSessionPeerMismatch) {
		t.Fatalf("BindSessionPeer error = %v, want ErrSessionPeerMismatch", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerAllowsPartialCallerAncestryWhenAnchorWasSeen(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(1002)
	requester := testProcessIdentity(500, 1, "/bin/zsh")
	inspectErr := errors.New("process exited while walking ancestry")
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: func(pid int) ([]peercred.ProcessIdentity, error) {
		switch pid {
		case creator.PID:
			return []peercred.ProcessIdentity{
				testProcessIdentity(creator.PID, requester.PID, creator.ExecutablePath),
				requester,
				testProcessIdentity(1, 0, "/sbin/launchd"),
			}, nil
		case caller.PID:
			return []peercred.ProcessIdentity{
				testProcessIdentity(caller.PID, requester.PID, caller.ExecutablePath),
				requester,
			}, inspectErr
		default:
			return nil, peercred.ErrMissingMetadata
		}
	}}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); err != nil {
		t.Fatalf("ValidateSessionPeer returned error with anchor in partial ancestry: %v", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerRejectsPartialCallerAncestryWhenAnchorWasNotSeen(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(1002)
	creatorRequester := testProcessIdentity(500, 1, "/bin/zsh")
	callerRequester := testProcessIdentity(600, 1, "/bin/zsh")
	inspectErr := errors.New("process exited while walking ancestry")
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: func(pid int) ([]peercred.ProcessIdentity, error) {
		switch pid {
		case creator.PID:
			return []peercred.ProcessIdentity{
				testProcessIdentity(creator.PID, creatorRequester.PID, creator.ExecutablePath),
				creatorRequester,
				testProcessIdentity(1, 0, "/sbin/launchd"),
			}, nil
		case caller.PID:
			return []peercred.ProcessIdentity{
				testProcessIdentity(caller.PID, callerRequester.PID, caller.ExecutablePath),
				callerRequester,
			}, inspectErr
		default:
			return nil, peercred.ErrMissingMetadata
		}
	}}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); !errors.Is(err, ErrSessionPeerMismatch) {
		t.Fatalf("ValidateSessionPeer error = %v, want ErrSessionPeerMismatch", err)
	} else if !strings.Contains(err.Error(), "process exited while walking ancestry") {
		t.Fatalf("ValidateSessionPeer error = %q, want caller ancestry inspection failure", err.Error())
	}
}

func TestProcessTreeSessionPeerAuthorizerRejectsUnrelatedTree(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	caller := testPeerInfo(2001)
	creatorRequester := testProcessIdentity(500, 1, "/bin/zsh")
	callerRequester := testProcessIdentity(600, 1, "/bin/zsh")
	lookup := map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, creatorRequester.PID, creator.ExecutablePath),
			creatorRequester,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
		caller.PID: {
			testProcessIdentity(caller.PID, callerRequester.PID, caller.ExecutablePath),
			callerRequester,
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	}
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(lookup)}

	binding, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy())
	if err != nil {
		t.Fatalf("BindSessionPeer returned error: %v", err)
	}
	if err := authorizer.ValidateSessionPeer(binding, caller); !errors.Is(err, ErrSessionPeerMismatch) {
		t.Fatalf("ValidateSessionPeer error = %v, want ErrSessionPeerMismatch", err)
	}
}

func TestProcessTreeSessionPeerAuthorizerDoesNotUseLaunchdAsAnchor(t *testing.T) {
	t.Parallel()

	creator := testPeerInfo(1001)
	authorizer := processTreeSessionPeerAuthorizer{processAncestry: ancestryLookup(map[int][]peercred.ProcessIdentity{
		creator.PID: {
			testProcessIdentity(creator.PID, 1, creator.ExecutablePath),
			testProcessIdentity(1, 0, "/sbin/launchd"),
		},
	})}

	if _, err := authorizer.BindSessionPeer(creator, request.DefaultSessionBindingPolicy()); !errors.Is(err, ErrSessionPeerMismatch) {
		t.Fatalf("BindSessionPeer error = %v, want ErrSessionPeerMismatch", err)
	}
}

func ancestryLookup(lookup map[int][]peercred.ProcessIdentity) func(int) ([]peercred.ProcessIdentity, error) {
	return func(pid int) ([]peercred.ProcessIdentity, error) {
		ancestry, ok := lookup[pid]
		if !ok {
			return nil, peercred.ErrMissingMetadata
		}
		return ancestry, nil
	}
}

func testPeerInfo(pid int) peercred.Info {
	return peercred.Info{
		UID:            501,
		GID:            20,
		PID:            pid,
		ExecutablePath: "/Applications/Agent Secret.app/Contents/MacOS/Agent Secret",
		CWD:            "/Users/example/project",
	}
}

func testProcessIdentity(pid int, parentPID int, executable string) peercred.ProcessIdentity {
	return peercred.ProcessIdentity{
		UID:            501,
		GID:            20,
		PID:            pid,
		ParentPID:      parentPID,
		ExecutablePath: executable,
		StartTime:      time.Unix(int64(pid), 0).UTC(),
	}
}
