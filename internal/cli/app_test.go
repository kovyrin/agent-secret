package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/bwsm"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/helperidentity"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func newTestApp(manager control.Manager, stdout io.Writer, stderr io.Writer) App {
	return NewApp(func() (control.Manager, error) {
		return manager, nil
	}, stdout, stderr)
}

func newTestAppWithDaemonManager(manager daemonManager, stdout io.Writer, stderr io.Writer) App {
	app := NewApp(nil, stdout, stderr)
	app.managerFactory = func() (daemonManager, error) {
		return manager, nil
	}
	return app
}

func testSessionBindingInfo() request.SessionBindingInfo {
	return request.SessionBindingInfo{
		Mode:          request.SessionBindingModeAncestor,
		AncestorDepth: 1,
		BoundProcess: request.SessionBindingProcess{
			PID:       501,
			ParentPID: 1,
			Name:      "zsh",
			Path:      "/bin/zsh",
		},
		CreatorProcess: request.SessionBindingProcess{
			PID:  502,
			Name: "agent-secret",
			Path: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		},
	}
}

func runConfigProfileExec(
	t *testing.T,
	app App,
	client *appFakeDaemonClient,
	stdout *bytes.Buffer,
	stderr *bytes.Buffer,
) request.ExecRequest {
	t.Helper()

	stdout.Reset()
	stderr.Reset()
	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--",
		os.Args[0], "-test.run=TestAppExecReReadsConfigAccountForRunningDaemon", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exec exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if len(client.requests) == 0 {
		t.Fatal("fake daemon did not receive exec request")
	}
	return client.requests[len(client.requests)-1]
}

func TestAppExecRunsChildWithApprovedEnvAndPassthrough(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=" + ref,
		"--",
		os.Args[0], "-test.run=TestAppExecRunsChildWithApprovedEnvAndPassthrough", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func TestAppExecUsesManagerClientWithoutSocket(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	client := &appFakeDaemonClient{
		execPayload: protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecUsesManagerClientWithoutSocket", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if manager.ensureCalls != 1 || manager.connectCalls != 1 {
		t.Fatalf("manager calls: ensure=%d connect=%d", manager.ensureCalls, manager.connectCalls)
	}
	if client.requestExecCalls != 1 || client.closeCalls != 1 {
		t.Fatalf("client calls: request=%d close=%d", client.requestExecCalls, client.closeCalls)
	}
	if len(client.startedPIDs) != 1 || len(client.completedExitCodes) != 1 {
		t.Fatalf("audit calls: started=%v completed=%v", client.startedPIDs, client.completedExitCodes)
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func TestAppSessionCreateUsesProfileAndPrintsJSON(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  deploy:
    reason: Run deploy workflow
    secrets:
      TOKEN: op://Example/Item/token
`)
	expiresAt := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
	client := &appFakeDaemonClient{
		sessionCreatePayload: protocol.SessionCreateResponsePayload{
			SessionID:      "asid_test",
			SessionToken:   "astok_test",
			SecretAliases:  []string{"TOKEN"},
			ExpiresAt:      expiresAt,
			MaxReads:       2,
			RemainingReads: 2,
			Binding:        testSessionBindingInfo(),
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"session",
		"create",
		"--account", "Work",
		"--max-reads", "2",
		"--json=compact",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if client.sessionCreateCalls != 1 || client.closeCalls != 1 {
		t.Fatalf("client calls: create=%d close=%d", client.sessionCreateCalls, client.closeCalls)
	}
	if len(client.sessionCreateRequests) != 1 {
		t.Fatalf("session create requests = %d", len(client.sessionCreateRequests))
	}
	req := client.sessionCreateRequests[0]
	if req.MaxReads != 2 || req.Secrets[0].Account != "Work" {
		t.Fatalf("session request = %+v", req)
	}
	var got sessionCreateOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v; stdout=%q", err, stdout.String())
	}
	if got.SessionID != "asid_test" || got.SessionToken != "astok_test" || got.RemainingReads != 2 || got.MaxReads != 2 {
		t.Fatalf("session create json = %+v", got)
	}
	if got.Binding.BoundProcess.Name != "zsh" || got.Binding.BoundProcess.PID != 501 {
		t.Fatalf("session create binding = %+v", got.Binding)
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("compact json should be one line, stdout=%q", stdout.String())
	}
	if strings.Contains(stdout.String(), "synthetic-secret-value") || strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("session create leaked secret: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAppSessionCreatePrintsText(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	expiresAt := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
	client := &appFakeDaemonClient{
		sessionCreatePayload: protocol.SessionCreateResponsePayload{
			SessionID:      "asid_text",
			SessionToken:   "astok_text",
			SecretAliases:  []string{"TOKEN"},
			ExpiresAt:      expiresAt,
			MaxReads:       1,
			RemainingReads: 1,
			Binding:        testSessionBindingInfo(),
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"session",
		"create",
		"--reason", "Deploy",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"session id: asid_text", "session token: astok_text", "reads: 1/1 remaining", "secrets: TOKEN", "bound process: zsh pid=501"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("session create stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestAppSessionList(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
	t.Run("list", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{
			sessionListPayload: protocol.SessionListResponsePayload{
				Sessions: []protocol.SessionInfoPayload{{
					SessionID:      "asid_test",
					Reason:         "Deploy workflow",
					CWD:            "/tmp/project",
					SecretAliases:  []string{"TOKEN"},
					ExpiresAt:      expiresAt,
					MaxReads:       2,
					RemainingReads: 1,
					Binding:        testSessionBindingInfo(),
				}},
			},
		}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "list"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		if client.sessionListCalls != 1 || client.closeCalls != 1 {
			t.Fatalf("client calls: list=%d close=%d", client.sessionListCalls, client.closeCalls)
		}
		for _, want := range []string{"asid_test", "reads=1/2", "cwd=/tmp/project", "secrets=TOKEN", "reason=Deploy workflow", "bound=zsh pid=501"} {
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("session list stdout = %q, want %q", stdout.String(), want)
			}
		}
		for _, forbidden := range []string{"session_token", "astok_test"} {
			if strings.Contains(stdout.String(), forbidden) {
				t.Fatalf("session list stdout = %q, must not include token data %q", stdout.String(), forbidden)
			}
		}
	})

	t.Run("list json", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{
			sessionListPayload: protocol.SessionListResponsePayload{
				Sessions: []protocol.SessionInfoPayload{{
					SessionID:      "asid_test",
					Reason:         "Deploy workflow",
					CWD:            "/tmp/project",
					SecretAliases:  []string{"TOKEN"},
					ExpiresAt:      expiresAt,
					MaxReads:       2,
					RemainingReads: 1,
					Binding:        testSessionBindingInfo(),
				}},
			},
		}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "list", "--json"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		var got sessionListOutput
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("decode session list json: %v; stdout=%q", err, stdout.String())
		}
		if len(got.Sessions) != 1 ||
			got.Sessions[0].SessionID != "asid_test" ||
			got.Sessions[0].CWD != "/tmp/project" ||
			got.Sessions[0].RemainingReads != 1 ||
			got.Sessions[0].Binding.BoundProcess.Name != "zsh" {
			t.Fatalf("session list json = %+v", got)
		}
		if strings.Contains(stdout.String(), "session_token") || strings.Contains(stdout.String(), "astok_") {
			t.Fatalf("session list json exposes a session token: %s", stdout.String())
		}
	})

	t.Run("list empty", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "list"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		if strings.TrimSpace(stdout.String()) != "no active sessions" {
			t.Fatalf("session list empty stdout = %q", stdout.String())
		}
	})
}

func TestAppSessionDestroy(t *testing.T) {
	t.Parallel()

	t.Run("destroy", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{
			sessionDestroyPayload: protocol.SessionDestroyResponsePayload{
				SessionID: "asid_test",
				Destroyed: true,
			},
		}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "destroy", "asid_test"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		if client.sessionDestroyCalls != 1 || client.closeCalls != 1 {
			t.Fatalf("client calls: destroy=%d close=%d", client.sessionDestroyCalls, client.closeCalls)
		}
		if len(client.sessionDestroyRequests) != 1 || client.sessionDestroyRequests[0].SessionID != "asid_test" {
			t.Fatalf("destroy requests = %+v", client.sessionDestroyRequests)
		}
		if !strings.Contains(stdout.String(), "destroyed session: asid_test") {
			t.Fatalf("session destroy stdout = %q", stdout.String())
		}
	})

	t.Run("destroy all", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{
			sessionDestroyPayload: protocol.SessionDestroyResponsePayload{
				Destroyed:      true,
				DestroyedCount: 2,
			},
		}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "destroy", "--all"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		if len(client.sessionDestroyRequests) != 1 || !client.sessionDestroyRequests[0].All {
			t.Fatalf("destroy requests = %+v", client.sessionDestroyRequests)
		}
		if !strings.Contains(stdout.String(), "destroyed sessions: 2") {
			t.Fatalf("session destroy --all stdout = %q", stdout.String())
		}
	})

	t.Run("destroy json", func(t *testing.T) {
		t.Parallel()

		client := &appFakeDaemonClient{
			sessionDestroyPayload: protocol.SessionDestroyResponsePayload{
				SessionID: "asid_test",
				Destroyed: true,
			},
		}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "destroy", "--json", "asid_test"})
		if code != 0 {
			t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
		}
		var got protocol.SessionDestroyResponsePayload
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("decode session destroy json: %v; stdout=%q", err, stdout.String())
		}
		if got.SessionID != "asid_test" || !got.Destroyed {
			t.Fatalf("session destroy json = %+v", got)
		}
	})
}

func TestAppSessionCommandFailures(t *testing.T) {
	t.Run("create random id", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		client := &appFakeDaemonClient{}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
		app.RandomReader = failingRandomReader{err: errors.New("entropy unavailable")}

		code := app.Run(context.Background(), []string{
			"session", "create",
			"--reason", "Deploy",
			"--account", "Work",
			"--secret", "TOKEN=op://Example/Item/token",
		})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "generate random id") {
			t.Fatalf("stderr = %q, want random id failure", stderr.String())
		}
		if client.sessionCreateCalls != 0 {
			t.Fatalf("session create calls = %d, want 0", client.sessionCreateCalls)
		}
	})

	t.Run("create daemon error", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		client := &appFakeDaemonClient{sessionCreateErr: errors.New("approval denied")}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{
			"session", "create",
			"--reason", "Deploy",
			"--account", "Work",
			"--secret", "TOKEN=op://Example/Item/token",
		})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "approval denied") {
			t.Fatalf("stderr = %q", stderr.String())
		}
		if client.sessionCreateCalls != 1 {
			t.Fatalf("session create calls = %d, want 1", client.sessionCreateCalls)
		}
	})

	t.Run("list daemon error", func(t *testing.T) {
		client := &appFakeDaemonClient{sessionListErr: errors.New("daemon unavailable")}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "list"})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "daemon unavailable") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("destroy daemon error", func(t *testing.T) {
		client := &appFakeDaemonClient{sessionDestroyErr: errors.New("session not found")}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{"session", "destroy", "asid_missing"})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "session not found") {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("with-session resolve error", func(t *testing.T) {
		root := t.TempDir()
		t.Chdir(root)
		client := &appFakeDaemonClient{sessionResolveErr: errors.New("session expired")}
		manager := &appFakeDaemonManager{
			socketPath: filepath.Join(t.TempDir(), "d.sock"),
			client:     client,
			status:     protocol.StatusPayload{PID: 1234},
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

		code := app.Run(context.Background(), []string{
			"with-session",
			"astok_test",
			"--cwd", root,
			"--allow-mutable-executable",
			"--",
			os.Args[0], "-test.run=TestAppSessionCommandFailures", "--", "child",
		})
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "session expired") {
			t.Fatalf("stderr = %q", stderr.String())
		}
		if len(client.startedPIDs) != 0 {
			t.Fatalf("started pids = %v, want none", client.startedPIDs)
		}
	})
}

func TestAppWithSessionRunsChildWithResolvedEnv(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	root := t.TempDir()
	t.Chdir(root)
	client := &appFakeDaemonClient{
		sessionResolvePayload: protocol.SessionResolveResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"with-session",
		"astok_test",
		"--cwd", root,
		"--only", "TOKEN",
		"--allow-mutable-executable",
		"--",
		os.Args[0], "-test.run=TestAppWithSessionRunsChildWithResolvedEnv", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if client.sessionResolveCalls != 1 || client.closeCalls != 1 {
		t.Fatalf("client calls: resolve=%d close=%d", client.sessionResolveCalls, client.closeCalls)
	}
	if len(client.sessionResolveRequests) != 1 {
		t.Fatalf("session resolve requests = %d", len(client.sessionResolveRequests))
	}
	req := client.sessionResolveRequests[0]
	if req.SessionToken != "astok_test" || req.ExpectedPeer.PID <= 0 || req.CWD == "" {
		t.Fatalf("session resolve request = %+v", req)
	}
	if len(req.RequestedAliases) != 1 || req.RequestedAliases[0] != "TOKEN" {
		t.Fatalf("requested aliases = %v, want TOKEN", req.RequestedAliases)
	}
	if len(client.startedPIDs) != 1 || len(client.completedExitCodes) != 1 {
		t.Fatalf("audit calls: started=%v completed=%v", client.startedPIDs, client.completedExitCodes)
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func TestAppGCPExecRunsChildWithIsolatedCloudSDKEnv(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_GCP_HELPER") == "1" {
		runAppGCPHelper()
		return
	}

	client := &appFakeDaemonClient{
		gcpCommandPayload: protocol.GCPCommandResponsePayload{
			Env: map[string]string{
				"CLOUDSDK_CONFIG":                 filepath.Join(t.TempDir(), "cloudsdk"),
				"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": filepath.Join(t.TempDir(), "access-token"),
				"CLOUDSDK_CORE_PROJECT":           "fixture-beta",
			},
			DeliveryMode: "token_file",
			ExpiresAt:    time.Now().Add(time.Minute),
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_GCP_HELPER", "1")
	t.Setenv("CLOUDSDK_CONFIG", "/ambient/config")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/ambient/adc.json")

	code := app.Run(context.Background(), []string{
		"gcp", "exec",
		"--reason", "Inspect logs",
		"--google-account", "work",
		"--project", "fixture-beta",
		"--service-account", "agent-beta@fixture-beta.iam.gserviceaccount.com",
		"--scope", "https://www.googleapis.com/auth/cloud-platform",
		"--allow-mutable-executable",
		"--",
		os.Args[0], "-test.run=TestAppGCPExecRunsChildWithIsolatedCloudSDKEnv", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp-env-ok" {
		t.Fatalf("stdout = %q, want gcp-env-ok", stdout.String())
	}
	if manager.ensureCalls != 1 || manager.connectCalls != 1 || client.requestGCPExecCalls != 1 {
		t.Fatalf("manager/client calls: ensure=%d connect=%d gcp=%d", manager.ensureCalls, manager.connectCalls, client.requestGCPExecCalls)
	}
	if len(client.startedPIDs) != 1 || len(client.completedExitCodes) != 1 {
		t.Fatalf("audit calls: started=%v completed=%v", client.startedPIDs, client.completedExitCodes)
	}
}

func TestAppGCPExecDryRunJSONDoesNotStartDaemon(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o750); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	writeExecutable(t, binDir, "gcloud")
	writeProfileConfig(t, root, `
version: 1
profiles:
  beta-logs:
    reason: Inspect beta logs
    ttl: 5m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
`)
	t.Setenv("PATH", binDir)
	manager := &appFakeDaemonManager{ensureErr: errors.New("daemon should not start")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gcp", "exec",
		"--config", filepath.Join(root, "agent-secret.yml"),
		"--profile", "beta-logs",
		"--dry-run",
		"--json",
		"--allow-mutable-executable",
		"--",
		"gcloud", "logging", "read", "severity>=ERROR",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 {
		t.Fatalf("dry run touched daemon: ensure=%d connect=%d", manager.ensureCalls, manager.connectCalls)
	}
	var output gcpExecDryRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("unmarshal dry-run json: %v\n%s", err, stdout.String())
	}
	if !output.OK || output.WouldSpawn || output.Request.Project != "fixture-beta" {
		t.Fatalf("unexpected dry-run output: %+v", output)
	}
	if !strings.Contains(strings.Join(output.Notes, " "), "did not mint") {
		t.Fatalf("dry-run notes did not mention minting: %+v", output.Notes)
	}
}

func TestAppGCPSessionCreateListAndDestroyOutput(t *testing.T) {
	root := t.TempDir()
	writeProfileConfig(t, root, `
version: 1
profiles:
  beta-debug:
    reason: Debug beta
    ttl: 30m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-debug@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
`)
	expiresAt := time.Date(2026, 5, 21, 12, 30, 0, 0, time.UTC)
	client := &appFakeDaemonClient{
		gcpSessionCreatePayload: protocol.GCPSessionCreateResponsePayload{
			SessionHandle:          "asess_123",
			SessionAuditID:         "asess_123:deadbeef",
			ExpiresAt:              expiresAt,
			RemainingCommandStarts: 12,
		},
		gcpSessionListPayload: protocol.GCPSessionListResponsePayload{
			Sessions: []protocol.GCPSessionInfo{
				{
					SessionAuditID:         "asess_123:deadbeef",
					ProfileName:            "beta-debug",
					GoogleAccount:          "work",
					Project:                "fixture-beta",
					ServiceAccount:         "agent-beta-debug@fixture-beta.iam.gserviceaccount.com",
					RemainingCommandStarts: 12,
					UsableFromCWD:          true,
				},
			},
		},
		gcpSessionDestroyPayload: protocol.GCPSessionDestroyResponsePayload{
			Destroyed:      true,
			SessionAuditID: "asess_123:deadbeef",
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"gcp", "session", "create",
		"--config", filepath.Join(root, "agent-secret.yml"),
		"--profile", "beta-debug",
		"--max-command-starts", "12",
		"--json",
	})
	if code != 0 {
		t.Fatalf("session create exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var created gcpSessionCreateOutput
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal session create json: %v\n%s", err, stdout.String())
	}
	if created.SessionHandle != "asess_123" || created.RemainingCommandStarts != 12 {
		t.Fatalf("unexpected create output: %+v", created)
	}
	normalizedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}
	if len(client.gcpSessionCreateRequests) != 1 || client.gcpSessionCreateRequests[0].ProjectRoot != normalizedRoot {
		t.Fatalf("session create requests = %+v", client.gcpSessionCreateRequests)
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{"gcp", "session", "list"})
	if code != 0 {
		t.Fatalf("session list exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "asess_123:deadbeef") || !strings.Contains(stdout.String(), "usable from cwd") {
		t.Fatalf("session list output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{"gcp", "session", "destroy", "--json", "asess_123"})
	if code != 0 {
		t.Fatalf("session destroy exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var destroyed gcpSessionDestroyOutput
	if err := json.Unmarshal(stdout.Bytes(), &destroyed); err != nil {
		t.Fatalf("unmarshal session destroy json: %v\n%s", err, stdout.String())
	}
	if !destroyed.Destroyed || destroyed.SessionAuditID != "asess_123:deadbeef" {
		t.Fatalf("unexpected destroy output: %+v", destroyed)
	}
	if manager.ensureCalls != 3 || manager.connectCalls != 3 ||
		client.createGCPSessionCalls != 1 ||
		client.listGCPSessionsCalls != 1 ||
		client.destroyGCPSessionCalls != 1 {
		t.Fatalf("manager/client calls: ensure=%d connect=%d create=%d list=%d destroy=%d",
			manager.ensureCalls,
			manager.connectCalls,
			client.createGCPSessionCalls,
			client.listGCPSessionsCalls,
			client.destroyGCPSessionCalls,
		)
	}
}

func TestAppGCPTextAndEmptyJSONOutputs(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o750); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	writeExecutable(t, binDir, "gcloud")
	writeProfileConfig(t, root, `
version: 1
profiles:
  beta-debug:
    reason: Debug beta
    ttl: 30m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-debug@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
`)
	t.Setenv("PATH", binDir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	dryRunApp := newTestAppWithDaemonManager(&appFakeDaemonManager{ensureErr: errors.New("daemon should not start")}, &stdout, &stderr)
	code := dryRunApp.Run(context.Background(), []string{
		"gcp", "exec",
		"--config", filepath.Join(root, "agent-secret.yml"),
		"--profile", "beta-debug",
		"--ttl", "5m",
		"--dry-run",
		"--allow-mutable-executable",
		"--",
		"gcloud", "logging", "read", "severity>=ERROR",
	})
	if code != 0 {
		t.Fatalf("dry-run text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"agent-secret gcp exec dry run: ok",
		"would prompt: true",
		"project: fixture-beta",
		"service_account: agent-beta-debug@fixture-beta.iam.gserviceaccount.com",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run text missing %q:\n%s", want, stdout.String())
		}
	}

	expiresAt := time.Date(2026, 5, 21, 12, 30, 0, 0, time.UTC)
	client := &appFakeDaemonClient{
		gcpSessionCreatePayload: protocol.GCPSessionCreateResponsePayload{
			SessionHandle:          "asess_123",
			SessionAuditID:         "asess_123:deadbeef",
			ExpiresAt:              expiresAt,
			RemainingCommandStarts: 12,
		},
		gcpSessionDestroyPayload: protocol.GCPSessionDestroyResponsePayload{Destroyed: true},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	stdout.Reset()
	stderr.Reset()
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	code = app.Run(context.Background(), []string{
		"gcp", "session", "create",
		"--config", filepath.Join(root, "agent-secret.yml"),
		"--profile", "beta-debug",
	})
	if code != 0 {
		t.Fatalf("session create text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "gcp session: asess_123") ||
		!strings.Contains(stdout.String(), "remaining_command_starts: 12") {
		t.Fatalf("session create text output = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	client.gcpSessionListPayload = protocol.GCPSessionListResponsePayload{}
	code = app.Run(context.Background(), []string{"gcp", "session", "list", "--json"})
	if code != 0 {
		t.Fatalf("session list json exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var listOutput gcpSessionListOutput
	if err := json.Unmarshal(stdout.Bytes(), &listOutput); err != nil {
		t.Fatalf("unmarshal session list json: %v\n%s", err, stdout.String())
	}
	if len(listOutput.Sessions) != 0 {
		t.Fatalf("session list json sessions = %+v, want none", listOutput.Sessions)
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{"gcp", "session", "list"})
	if code != 0 {
		t.Fatalf("session list empty text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp sessions: none" {
		t.Fatalf("session list empty text = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	client.gcpSessionDestroyPayload = protocol.GCPSessionDestroyResponsePayload{Destroyed: true}
	code = app.Run(context.Background(), []string{"gcp", "session", "destroy", "asess_123"})
	if code != 0 {
		t.Fatalf("session destroy text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp session: destroyed" {
		t.Fatalf("session destroy text = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	client.gcpSessionDestroyPayload = protocol.GCPSessionDestroyResponsePayload{}
	code = app.Run(context.Background(), []string{"gcp", "session", "destroy", "asess_missing"})
	if code != 0 {
		t.Fatalf("session destroy missing text exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp session: not found" {
		t.Fatalf("session destroy missing text = %q", stdout.String())
	}
}

func TestAppGCPWithSessionRunsChildWithIsolatedCloudSDKEnv(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_GCP_HELPER") == "1" {
		runAppGCPHelper()
		return
	}

	client := &appFakeDaemonClient{
		gcpCommandPayload: protocol.GCPCommandResponsePayload{
			Env: map[string]string{
				"CLOUDSDK_CONFIG":                 filepath.Join(t.TempDir(), "cloudsdk"),
				"CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": filepath.Join(t.TempDir(), "access-token"),
				"CLOUDSDK_CORE_PROJECT":           "fixture-beta",
			},
			DeliveryMode: "token_file",
			ExpiresAt:    time.Now().Add(time.Minute),
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_GCP_HELPER", "1")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/ambient/adc.json")

	code := app.Run(context.Background(), []string{
		"gcp", "with-session", "asess_123",
		"--allow-mutable-executable",
		"--",
		os.Args[0], "-test.run=TestAppGCPWithSessionRunsChildWithIsolatedCloudSDKEnv", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp-env-ok" {
		t.Fatalf("stdout = %q, want gcp-env-ok", stdout.String())
	}
	if client.useGCPSessionCalls != 1 || len(client.gcpSessionUseRequests) != 1 {
		t.Fatalf("with-session calls = %d requests=%+v", client.useGCPSessionCalls, client.gcpSessionUseRequests)
	}
	if client.gcpSessionUseRequests[0].SessionHandle != "asess_123" {
		t.Fatalf("with-session request = %+v", client.gcpSessionUseRequests[0])
	}
}

func TestAppGCPAuthStatusLoginAndLogoutOutput(t *testing.T) {
	t.Parallel()

	client := &appFakeDaemonClient{
		gcpAuthStatusPayload: protocol.GCPAuthStatusResponsePayload{
			Accounts: []protocol.GCPAuthAccountInfo{
				{
					GoogleAccount: "personal",
					Email:         "oleksiy@kovyrin.net",
					Scopes:        []string{"https://www.googleapis.com/auth/cloud-platform"},
					UpdatedAt:     time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
				},
			},
		},
		gcpAuthLoginPayload: protocol.GCPAuthLoginResponsePayload{
			Account: protocol.GCPAuthAccountInfo{
				GoogleAccount: "personal",
				Email:         "oleksiy@kovyrin.net",
				Scopes:        []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		},
		gcpAuthLogoutPayload: protocol.GCPAuthLogoutResponsePayload{
			GoogleAccount: "personal",
			Deleted:       true,
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"gcp", "auth", "status"}); code != 0 {
		t.Fatalf("auth status exit = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "personal email=oleksiy@kovyrin.net") {
		t.Fatalf("auth status stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"gcp", "auth", "login", "--google-account", "personal", "--expected-email", "oleksiy@kovyrin.net"}); code != 0 {
		t.Fatalf("auth login exit = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "gcp auth: logged in") ||
		len(client.gcpAuthLoginRequests) != 1 ||
		client.gcpAuthLoginRequests[0].ExpectedEmail != "oleksiy@kovyrin.net" {
		t.Fatalf("auth login stdout=%q requests=%+v", stdout.String(), client.gcpAuthLoginRequests)
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"gcp", "auth", "logout", "--google-account", "personal"}); code != 0 {
		t.Fatalf("auth logout exit = %d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp auth: removed personal" || client.gcpAuthLogoutCalls != 1 {
		t.Fatalf("auth logout stdout=%q calls=%d", stdout.String(), client.gcpAuthLogoutCalls)
	}
}

func TestAppGCPAuthJSONAndEmptyTextOutput(t *testing.T) {
	t.Parallel()

	client := &appFakeDaemonClient{
		gcpAuthLoginPayload: protocol.GCPAuthLoginResponsePayload{
			Account: protocol.GCPAuthAccountInfo{
				GoogleAccount: "personal",
				Email:         "oleksiy@kovyrin.net",
				Scopes:        []string{"https://www.googleapis.com/auth/cloud-platform"},
			},
		},
		gcpAuthLogoutPayload: protocol.GCPAuthLogoutResponsePayload{
			GoogleAccount: "personal",
			Deleted:       false,
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"gcp", "auth", "status"}); code != 0 {
		t.Fatalf("auth status exit = %d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp auth: no bootstrap accounts configured" {
		t.Fatalf("empty auth status stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"gcp", "auth", "status", "--json"}); code != 0 {
		t.Fatalf("auth status json exit = %d stderr=%q", code, stderr.String())
	}
	var status gcpAuthStatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal status json: %v\n%s", err, stdout.String())
	}
	if status.SchemaVersion != "1" || len(status.Accounts) != 0 {
		t.Fatalf("unexpected status json: %+v", status)
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{
		"gcp", "auth", "login",
		"--google-account", "personal",
		"--json",
	}); code != 0 {
		t.Fatalf("auth login json exit = %d stderr=%q", code, stderr.String())
	}
	var login gcpAuthLoginOutput
	if err := json.Unmarshal(stdout.Bytes(), &login); err != nil {
		t.Fatalf("unmarshal login json: %v\n%s", err, stdout.String())
	}
	if login.SchemaVersion != "1" || login.Account.GoogleAccount != "personal" {
		t.Fatalf("unexpected login json: %+v", login)
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"gcp", "auth", "logout", "--google-account", "personal"}); code != 0 {
		t.Fatalf("auth logout exit = %d stderr=%q", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "gcp auth: personal was not configured" {
		t.Fatalf("auth logout missing stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"gcp", "auth", "logout", "--google-account", "personal", "--json"}); code != 0 {
		t.Fatalf("auth logout json exit = %d stderr=%q", code, stderr.String())
	}
	var logout gcpAuthLogoutOutput
	if err := json.Unmarshal(stdout.Bytes(), &logout); err != nil {
		t.Fatalf("unmarshal logout json: %v\n%s", err, stdout.String())
	}
	if logout.SchemaVersion != "1" || logout.GoogleAccount != "personal" || logout.Deleted {
		t.Fatalf("unexpected logout json: %+v", logout)
	}
}

func TestAppGCPAuthCommandsReportDaemonRequestFailures(t *testing.T) {
	t.Parallel()

	client := &appFakeDaemonClient{gcpAuthErr: errors.New("auth unavailable")}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	tests := [][]string{
		{"gcp", "auth", "status"},
		{"gcp", "auth", "login", "--google-account", "personal"},
		{"gcp", "auth", "logout", "--google-account", "personal"},
	}
	for _, args := range tests {
		stdout.Reset()
		stderr.Reset()
		if code := app.Run(context.Background(), args); code != 1 {
			t.Fatalf("%v exit = %d, want 1", args, code)
		}
		if !strings.Contains(stderr.String(), "auth unavailable") {
			t.Fatalf("%v stderr = %q", args, stderr.String())
		}
	}
	if client.gcpAuthStatusCalls != 1 || client.gcpAuthLoginCalls != 1 || client.gcpAuthLogoutCalls != 1 {
		t.Fatalf("auth calls: status=%d login=%d logout=%d", client.gcpAuthStatusCalls, client.gcpAuthLoginCalls, client.gcpAuthLogoutCalls)
	}
}

func TestAppGCPCommandsReportDaemonStartupFailures(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o750); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	writeExecutable(t, binDir, "gcloud")
	writeProfileConfig(t, root, `
version: 1
profiles:
  beta-debug:
    reason: Debug beta
    ttl: 30m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-debug@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
`)
	t.Setenv("PATH", binDir)
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     &appFakeDaemonClient{},
		ensureErr:  errors.New("daemon unavailable"),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	tests := [][]string{
		{
			"gcp", "exec",
			"--reason", "Inspect logs",
			"--google-account", "work",
			"--project", "fixture-beta",
			"--service-account", "agent-beta-debug@fixture-beta.iam.gserviceaccount.com",
			"--scope", "https://www.googleapis.com/auth/cloud-platform",
			"--allow-mutable-executable",
			"--",
			"gcloud", "logging", "read", "severity>=ERROR",
		},
		{
			"gcp", "session", "create",
			"--config", filepath.Join(root, "agent-secret.yml"),
			"--profile", "beta-debug",
		},
		{"gcp", "session", "list"},
		{"gcp", "session", "destroy", "asess_123"},
		{"gcp", "with-session", "asess_123", "--allow-mutable-executable", "--", "gcloud", "compute", "instances", "list"},
		{"gcp", "auth", "status"},
		{"gcp", "auth", "login", "--google-account", "personal"},
		{"gcp", "auth", "logout", "--google-account", "personal"},
	}
	for _, args := range tests {
		stdout.Reset()
		stderr.Reset()
		if code := app.Run(context.Background(), args); code != 1 {
			t.Fatalf("%v exit = %d, want 1", args, code)
		}
		if !strings.Contains(stderr.String(), "start daemon: daemon unavailable") {
			t.Fatalf("%v stderr = %q", args, stderr.String())
		}
	}
}

func TestAppItemDescribePrintsMetadataWithoutSecretValues(t *testing.T) {
	t.Parallel()

	client := &appFakeDaemonClient{
		itemDescribePayload: protocol.ItemDescribeResponsePayload{
			Item: itemmetadata.Metadata{
				Account: "example.1password.com",
				Vault:   "Demo Infra",
				Item:    "Deploy Key",
				Fields: []itemmetadata.Field{
					{
						Label:     "private key",
						Type:      "Concealed",
						Concealed: true,
						Ref:       "op://Demo Infra/Deploy Key/private key",
					},
				},
			},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"item",
		"describe",
		"--account", "example.1password.com",
		"--format", "env-refs",
		"--prefix", "DEMO",
		"op://Demo Infra/Deploy Key",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if want := "DEMO_PRIVATE_KEY='op://Demo Infra/Deploy Key/private key'\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if manager.ensureCalls != 1 || manager.connectCalls != 1 {
		t.Fatalf("manager calls: ensure=%d connect=%d", manager.ensureCalls, manager.connectCalls)
	}
	if client.itemDescribeCalls != 1 || client.closeCalls != 1 {
		t.Fatalf("client calls: itemDescribe=%d close=%d", client.itemDescribeCalls, client.closeCalls)
	}
	if len(client.itemDescribeRequests) != 1 {
		t.Fatalf("item describe requests = %d", len(client.itemDescribeRequests))
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-secret-value") {
		t.Fatalf("output leaked secret-looking canary")
	}
}

func TestAppBitwardenTokenInstallStatusAndRemove(t *testing.T) {
	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store
	app.Stdin = strings.NewReader("synthetic-token-value\n")

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
		"--from-stdin",
	})
	if code != 0 {
		t.Fatalf("install exit code = %d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-value") {
		t.Fatalf("token install leaked token value: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if got := store.tokens["work"].AccessToken; got != "synthetic-token-value" {
		t.Fatalf("stored token = %q", got)
	}
	if store.interactivePuts != 0 {
		t.Fatalf("stdin install used interactive store writes: %d", store.interactivePuts)
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"status",
		"--alias", "work",
		"--json",
	})
	if code != 0 {
		t.Fatalf("status json exit code = %d stderr=%q", code, stderr.String())
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &statusPayload); err != nil {
		t.Fatalf("status json did not decode: %v stdout=%q", err, stdout.String())
	}
	if statusPayload["status"] != "installed" || statusPayload["ok"] != true {
		t.Fatalf("status json payload = %+v", statusPayload)
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"status",
		"--alias", "work",
	})
	if code != 0 {
		t.Fatalf("status exit code = %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `token alias "work": installed`) {
		t.Fatalf("status stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-value") {
		t.Fatalf("token status leaked token value")
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"remove",
		"--alias", "work",
	})
	if code != 0 {
		t.Fatalf("remove exit code = %d stderr=%q", code, stderr.String())
	}
	if _, ok := store.tokens["work"]; ok {
		t.Fatal("remove left token in store")
	}
}

func TestAppBitwardenTokenStatusMissingJSON(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"status",
		"--alias", "work",
		"--json",
	})
	if code != 1 {
		t.Fatalf("status exit code = %d stderr=%q", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal status json: %v; stdout=%q", err, stdout.String())
	}
	if payload["status"] != "missing" || payload["ok"] != false {
		t.Fatalf("status payload = %+v", payload)
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAppBitwardenTokenInstallPromptsInteractively(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store
	app.SecretPrompt = func(prompt string) (string, error) {
		if !strings.Contains(prompt, `alias "work"`) {
			t.Fatalf("prompt = %q, want alias", prompt)
		}
		return "synthetic-token-value\n", nil
	}

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
	})
	if code != 0 {
		t.Fatalf("interactive install exit code = %d stderr=%q", code, stderr.String())
	}
	if got := store.tokens["work"].AccessToken; got != "synthetic-token-value" {
		t.Fatalf("stored token = %q", got)
	}
	if store.interactivePuts != 1 {
		t.Fatalf("interactive install writes = %d, want 1", store.interactivePuts)
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-value") {
		t.Fatalf("interactive token install leaked token value: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `token alias "work": installed`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAppBitwardenTokenInstallPromptFailureDoesNotStore(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store
	app.SecretPrompt = func(string) (string, error) {
		return "", errors.New("no terminal")
	}

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
	})
	if code != 1 {
		t.Fatalf("interactive install failure exit code = %d stderr=%q", code, stderr.String())
	}
	if _, ok := store.tokens["work"]; ok {
		t.Fatal("failed interactive install stored token")
	}
	if !strings.Contains(stderr.String(), "read Bitwarden token interactively") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAppBitwardenTokenInstallJSONAndFailures(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store
	app.Stdin = strings.NewReader("synthetic-token-value\n")

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "work",
		"--from-stdin",
		"--json",
	})
	if code != 0 {
		t.Fatalf("install exit code = %d stderr=%q", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal install json: %v; stdout=%q", err, stdout.String())
	}
	if payload["status"] != "installed" || payload["ok"] != true {
		t.Fatalf("install payload = %+v", payload)
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-token-value") {
		t.Fatalf("install json leaked token")
	}

	stdout.Reset()
	stderr.Reset()
	app.Stdin = strings.NewReader(" \n ")
	code = app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"install",
		"--alias", "empty",
		"--from-stdin",
	})
	if code != 1 {
		t.Fatalf("empty install exit code = %d stderr=%q", code, stderr.String())
	}
	if _, ok := store.tokens["empty"]; ok {
		t.Fatal("empty token was stored")
	}
}

func TestAppBitwardenTokenRemoveMissingJSON(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{tokens: make(map[string]bwsm.Token)}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"remove",
		"--alias", "missing",
		"--json",
	})
	if code != 0 {
		t.Fatalf("remove exit code = %d stderr=%q", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal remove json: %v; stdout=%q", err, stdout.String())
	}
	if payload["status"] != "missing" || payload["ok"] != false {
		t.Fatalf("remove payload = %+v", payload)
	}
}

func TestAppBitwardenTokenStoreErrors(t *testing.T) {
	t.Parallel()

	store := &fakeBitwardenStore{
		tokens: make(map[string]bwsm.Token),
		getErr: errors.New("keychain denied"),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	app.BitwardenTokens = store

	code := app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"status",
		"--alias", "work",
	})
	if code != 1 {
		t.Fatalf("status exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), `inspect Bitwarden token alias "work": keychain denied`) {
		t.Fatalf("status stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	store.getErr = nil
	store.deleteErr = errors.New("delete denied")
	code = app.Run(context.Background(), []string{
		"bitwarden",
		"secrets-manager",
		"token",
		"remove",
		"--alias", "work",
	})
	if code != 1 {
		t.Fatalf("remove exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), `remove Bitwarden token alias "work": delete denied`) {
		t.Fatalf("remove stderr = %q", stderr.String())
	}
}

func TestAppBitwardenRejectsUnsupportedOperation(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(nil, &stdout, &stderr)
	code := app.runBitwarden(context.Background(), Command{
		Kind: KindBitwarden,
		BitwardenOptions: BitwardenCommandOptions{
			Operation: BitwardenTokenOperation("unknown"),
			Alias:     "work",
		},
	})
	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "unsupported Bitwarden operation") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestAppItemDescribePrintsTextMetadata(t *testing.T) {
	t.Parallel()

	client := &appFakeDaemonClient{
		itemDescribePayload: protocol.ItemDescribeResponsePayload{
			Item: itemmetadata.Metadata{
				Account:  "example.1password.com",
				Vault:    "Demo Infra",
				Item:     "Deploy Key",
				Category: "api_credential",
				Fields: []itemmetadata.Field{
					{
						Label:     "credential",
						Type:      "Concealed",
						Concealed: true,
						Ref:       "op://Demo Infra/Deploy Key/credential",
					},
					{
						Label:   "hostname",
						Type:    "Text",
						Section: "connection",
						Ref:     "op://Demo Infra/Deploy Key/connection/hostname",
					},
				},
			},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"item",
		"describe",
		"--account", "example.1password.com",
		"op://Demo Infra/Deploy Key",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"item:",
		"Deploy Key",
		"category:",
		"api_credential",
		"vault:",
		"Demo Infra",
		"account:",
		"example.1password.com",
		"fields:",
		"CREDENTIAL",
		"connection/hostname",
		"op://Demo Infra/Deploy Key/credential",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("text output missing %q:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-secret-value") {
		t.Fatalf("output leaked secret-looking canary")
	}
}

func TestAppItemDescribeUsesConfigAccountByDefault(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	configPath := filepath.Join(root, "agent-secret.yml")
	if err := os.WriteFile(configPath, []byte("version: 1\naccount: fixture.1password.com\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	client := &appFakeDaemonClient{
		itemDescribePayload: protocol.ItemDescribeResponsePayload{
			Item: itemmetadata.Metadata{
				Account: "fixture.1password.com",
				Vault:   "Fixture Infra",
				Item:    "Probe",
			},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"item",
		"describe",
		"--config", configPath,
		"--format", "json",
		"op://Fixture Infra/Probe",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if len(client.itemDescribeRequests) != 1 {
		t.Fatalf("item describe requests = %d", len(client.itemDescribeRequests))
	}
	if got := client.itemDescribeRequests[0].Account; got != "fixture.1password.com" {
		t.Fatalf("request account = %q, want fixture.1password.com", got)
	}
	if !strings.Contains(stdout.String(), `"account": "fixture.1password.com"`) {
		t.Fatalf("json output missing account: %s", stdout.String())
	}
}

func TestAppExecRetriesOnceWhenDaemonRetiresBeforeSpawn(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	retiredClient := &appFakeDaemonClient{
		requestErr: &control.ProtocolError{Code: protocol.ErrorCodeDaemonStopped, Message: "daemon stopped"},
	}
	freshClient := &appFakeDaemonClient{
		execPayload: protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		clients:    []daemonClient{retiredClient, freshClient},
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecRetriesOnceWhenDaemonRetiresBeforeSpawn", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if manager.ensureCalls != 2 || manager.connectCalls != 2 {
		t.Fatalf("manager calls: ensure=%d connect=%d, want 2 each", manager.ensureCalls, manager.connectCalls)
	}
	if retiredClient.requestExecCalls != 1 || retiredClient.closeCalls != 1 {
		t.Fatalf("retired client calls: request=%d close=%d", retiredClient.requestExecCalls, retiredClient.closeCalls)
	}
	if freshClient.requestExecCalls != 1 || freshClient.closeCalls != 1 {
		t.Fatalf("fresh client calls: request=%d close=%d", freshClient.requestExecCalls, freshClient.closeCalls)
	}
	if len(freshClient.startedPIDs) != 1 || len(freshClient.completedExitCodes) != 1 {
		t.Fatalf("fresh client audit calls: started=%v completed=%v", freshClient.startedPIDs, freshClient.completedExitCodes)
	}
	if strings.Contains(stderr.String(), "request rejected") {
		t.Fatalf("stderr reported pre-retry rejection: %q", stderr.String())
	}
}

func TestAppExecReportsBackgroundHelperRefreshBeforeRequest(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	client := &appFakeDaemonClient{
		execPayload: protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
		repairResult: control.RepairResult{
			Status: control.RepairStatusRefreshed,
			PID:    1234,
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecReportsBackgroundHelperRefreshBeforeRequest", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "Activating Agent Secret local service") {
		t.Fatalf("stderr = %q, want activation status", stderr.String())
	}
	if manager.repairCalls != 1 || manager.connectCalls != 1 || client.requestExecCalls != 1 {
		t.Fatalf("calls: repair=%d connect=%d request=%d", manager.repairCalls, manager.connectCalls, client.requestExecCalls)
	}
}

func TestAppExecRefusesUnexpectedBackgroundHelperBeforeSecretRequest(t *testing.T) {
	client := &appFakeDaemonClient{
		execPayload: protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		repairErr:  fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecRefusesUnexpectedBackgroundHelperBeforeSecretRequest", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "unexpected local service") ||
		!strings.Contains(stderr.String(), "Details: unexpected background helper: untrusted peer") ||
		!strings.Contains(stderr.String(), "agent-secret install-cli --force") {
		t.Fatalf("stderr = %q, want unexpected helper guidance", stderr.String())
	}
	if manager.connectCalls != 0 || client.requestExecCalls != 0 {
		t.Fatalf("secret request reached helper: connect=%d request=%d", manager.connectCalls, client.requestExecCalls)
	}
	if strings.Contains(stdout.String(), "synthetic-secret-value") || strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("secret leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAppExecReReadsConfigAccountForRunningDaemon(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	root := t.TempDir()
	t.Chdir(root)
	writeExecutable(t, root, "unused-tool")
	client := &appFakeDaemonClient{
		execPayload: protocol.ExecResponsePayload{
			Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
			SecretAliases: []string{"TOKEN"},
		},
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		client:     client,
		status:     protocol.StatusPayload{PID: 1234},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  deploy:
    account: First Account
    reason: Run helper
    secrets:
      TOKEN: op://Example/Item/token
`)
	first := runConfigProfileExec(t, app, client, &stdout, &stderr)

	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  deploy:
    account: Second Account
    reason: Run helper
    secrets:
      TOKEN: op://Example/Item/token
`)
	second := runConfigProfileExec(t, app, client, &stdout, &stderr)

	if first.Secrets[0].Account != "First Account" {
		t.Fatalf("first request account = %q, want First Account", first.Secrets[0].Account)
	}
	if second.Secrets[0].Account != "Second Account" {
		t.Fatalf("second request account = %q, want Second Account", second.Secrets[0].Account)
	}
	if manager.ensureCalls != 2 || manager.connectCalls != 2 {
		t.Fatalf("manager calls: ensure=%d connect=%d, want 2 each", manager.ensureCalls, manager.connectCalls)
	}
}

func TestAppExecRunsChildWithEnvFileSecretsAndPlainEnv(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	envFilePath := filepath.Join(t.TempDir(), ".env")
	envFile := "TOKEN=" + ref + "\nPLAIN_ENV=from-file\n"
	if err := os.WriteFile(envFilePath, []byte(envFile), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")
	t.Setenv("AGENT_SECRET_APP_EXPECT_PLAIN", "from-file")
	t.Setenv("TOKEN", "parent-token")
	t.Setenv("PLAIN_ENV", "parent")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--env-file", envFilePath,
		"--",
		os.Args[0], "-test.run=TestAppExecRunsChildWithEnvFileSecretsAndPlainEnv", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
}

func TestAppExecStopsBeforeSpawnOnApprovalDenial(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: false}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecStopsBeforeSpawnOnApprovalDenial", "--", "child",
	})
	if code == 0 {
		t.Fatal("denied request unexpectedly succeeded")
	}
	if strings.Contains(stdout.String(), "env-ok") {
		t.Fatalf("child appears to have run after denial: stdout=%q", stdout.String())
	}
}

func TestAppExecAllowsChildAfterDaemonStoppedStartedAudit(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	client, events, cleanup := startPostStartStoppedAppDaemon(t)
	defer cleanup()
	var stdout lockedBuffer
	var stderr lockedBuffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecAllowsChildAfterDaemonStoppedStartedAudit", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if !postStartStoppedDaemonSaw(events, protocol.TypeCommandStarted) {
		t.Fatal("fake daemon did not receive command.started")
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func TestAppDaemonStatusAndDoctor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	app.DoctorApproverCheck = func(context.Context) error { return nil }

	if code := app.Run(context.Background(), []string{"daemon", "status"}); code != 0 {
		t.Fatalf("daemon status exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "running pid=") {
		t.Fatalf("daemon status output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "audit log: writable") ||
		!strings.Contains(stdout.String(), "Agent Secret local service: ok") ||
		!strings.Contains(stdout.String(), "socket directory: private") ||
		!strings.Contains(stdout.String(), "native approver: ok") ||
		!strings.Contains(stdout.String(), "1password desktop integration: ok") {
		t.Fatalf("doctor output missing diagnostics: %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "status", "--json"}); code != 0 {
		t.Fatalf("daemon status json exit=%d stderr=%q", code, stderr.String())
	}
	var status daemonStatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("daemon status json did not decode: %v\n%s", err, stdout.String())
	}
	if !status.Running || status.PID == 0 {
		t.Fatalf("daemon status json = %+v", status)
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor json exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var doctor doctorOutput
	if err := json.Unmarshal(stdout.Bytes(), &doctor); err != nil {
		t.Fatalf("doctor json did not decode: %v\n%s", err, stdout.String())
	}
	if !doctor.OK || doctor.Platform == "" || len(doctor.Checks) == 0 {
		t.Fatalf("doctor json = %+v", doctor)
	}
}

func TestAppDaemonJSONStartStopAndFailures(t *testing.T) {
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		status:     protocol.StatusPayload{PID: 4321},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"daemon", "start", "--json"}); code != 0 {
		t.Fatalf("daemon start json exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var status daemonStatusOutput
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("daemon start json did not decode: %v\n%s", err, stdout.String())
	}
	if !status.Running || status.PID != 4321 || manager.startCalls != 1 || manager.statusCalls != 1 {
		t.Fatalf("daemon start json = %+v manager=%+v", status, manager)
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "stop", "--json"}); code != 0 {
		t.Fatalf("daemon stop json exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var stop daemonStopOutput
	if err := json.Unmarshal(stdout.Bytes(), &stop); err != nil {
		t.Fatalf("daemon stop json did not decode: %v\n%s", err, stdout.String())
	}
	if !stop.Stopped || manager.stopCalls != 1 {
		t.Fatalf("daemon stop json = %+v manager=%+v", stop, manager)
	}

	stdout.Reset()
	manager.statusErr = errors.New("status unavailable")
	if code := app.Run(context.Background(), []string{"daemon", "status", "--json"}); code != 1 {
		t.Fatalf("daemon status failure exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("daemon status failure json did not decode: %v\n%s", err, stdout.String())
	}
	if status.Running || !strings.Contains(status.Error, "status unavailable") {
		t.Fatalf("daemon status failure json = %+v", status)
	}

	stdout.Reset()
	manager.startErr = errors.New("start unavailable")
	if code := app.Run(context.Background(), []string{"daemon", "start", "--json"}); code != 1 {
		t.Fatalf("daemon start failure exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("daemon start failure json did not decode: %v\n%s", err, stdout.String())
	}
	if status.Running || !strings.Contains(status.Error, "start unavailable") {
		t.Fatalf("daemon start failure json = %+v", status)
	}

	stdout.Reset()
	manager.stopErr = errors.New("stop unavailable")
	if code := app.Run(context.Background(), []string{"daemon", "stop", "--json"}); code != 1 {
		t.Fatalf("daemon stop failure exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &stop); err != nil {
		t.Fatalf("daemon stop failure json did not decode: %v\n%s", err, stdout.String())
	}
	if stop.Stopped || !strings.Contains(stop.Error, "stop unavailable") {
		t.Fatalf("daemon stop failure json = %+v", stop)
	}
}

func TestAppDoctorReportsJSONDependencyFailures(t *testing.T) {
	homeFile := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(homeFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write home file: %v", err)
	}
	t.Setenv("HOME", homeFile)
	socketDir := filepath.Join(t.TempDir(), "insecure-socket-dir")
	//nolint:gosec // G301: intentionally creates an insecure socket dir for doctor failure coverage.
	if err := os.Mkdir(socketDir, 0o755); err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		repairErr:  errors.New("startup unavailable"),
		checkErr:   errors.New("desktop unavailable"),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = func(context.Context) error { return errors.New("approver unavailable") }

	if code := app.Run(context.Background(), []string{"doctor", "--json"}); code != 1 {
		t.Fatalf("doctor json failure exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var output doctorOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("doctor json failure did not decode: %v\n%s", err, stdout.String())
	}
	for _, name := range []string{
		"audit_log",
		"command_symlink",
		"local_service",
		"socket_directory",
		"native_approver",
		"1password_desktop_integration",
	} {
		check, found := findDoctorCheck(output.Checks, name)
		if !found || check.Error == "" {
			t.Fatalf("doctor check %s = %+v found=%t output=%+v", name, check, found, output)
		}
		if name == "local_service" {
			if check.Status != string(control.RepairStatusRepairRequired) {
				t.Fatalf("doctor check %s = %+v, want repair required", name, check)
			}
			continue
		}
		if check.Status != "failed" {
			t.Fatalf("doctor check %s = %+v, want failed", name, check)
		}
	}
}

func TestAppVersionDoesNotStartDaemon(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	manager := &appFakeDaemonManager{}
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"--version"}); code != 0 {
		t.Fatalf("version exit=%d stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "agent-secret dev" {
		t.Fatalf("version output = %q, want agent-secret dev", got)
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf(
			"version touched daemon manager: ensure=%d connect=%d status=%d",
			manager.ensureCalls,
			manager.connectCalls,
			manager.statusCalls,
		)
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"version", "--json"}); code != 0 {
		t.Fatalf("version json exit=%d stderr=%q", code, stderr.String())
	}
	var output versionOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("version json did not decode: %v\n%s", err, stdout.String())
	}
	if output.SchemaVersion != "1" || output.CLI != "agent-secret" || output.Display != "agent-secret dev" {
		t.Fatalf("version json output = %+v", output)
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("version json touched daemon manager")
	}
}

func TestAppExecDryRunJSONDoesNotStartDaemonPromptOrSpawn(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--dry-run",
		"--json",
		"--reuse-only",
		"--reason", "Preflight deploy",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool",
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var output execDryRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("dry-run json did not decode: %v\n%s", err, stdout.String())
	}
	if !output.OK || output.WouldPrompt || output.WouldSpawn {
		t.Fatalf("unexpected dry-run booleans: %+v", output)
	}
	if output.Request.Reason != "Preflight deploy" ||
		output.Request.Secrets[0].Ref != "op://Example/Item/token" ||
		!output.Request.ReuseOnly {
		t.Fatalf("unexpected dry-run request: %+v", output.Request)
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-secret-value") {
		t.Fatalf("dry-run leaked secret-looking canary")
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("dry-run touched daemon manager: %+v", manager)
	}
}

func TestAppExecDryRunTextDescribesPromptAndCommand(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--dry-run",
		"--reason", "Preflight deploy",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		"tool", "arg with space", "plain",
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"agent-secret exec dry run: ok",
		"would prompt: true",
		"would spawn: false",
		"command: '",
		"'arg with space'",
		"TOKEN=op://Example/Item/token account=Work",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run stdout = %q, want %q", stdout.String(), want)
		}
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("dry-run touched daemon manager: %+v", manager)
	}
}

func TestAppExecDryRunTextDescribesBitwardenScope(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, root, "tool")
	t.Chdir(root)
	t.Setenv("PATH", root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--dry-run",
		"--reason", "Preflight deploy",
		"--secret", "TOKEN=bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158",
		"--",
		"tool",
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"TOKEN=bws://work/be8e0ad8-d545-4017-a55a-b02f014d4158 source=work token_alias=work",
		"would prompt: true",
		"would spawn: false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run stdout = %q, want %q", stdout.String(), want)
		}
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("dry-run touched daemon manager: %+v", manager)
	}
}

func TestAppAgentContextAndProfilesJSON(t *testing.T) {
	root := t.TempDir()
	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  base:
    reason: Base
    secrets:
      BASE_TOKEN: op://Example/Base/token
  deploy:
    include:
      - base
    reason: Deploy
    secrets:
      DEPLOY_TOKEN: op://Example/Deploy/token
`)
	t.Chdir(root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"agent-context", "--json"}); code != 0 {
		t.Fatalf("agent-context exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var contextOutput agentContextOutput
	if err := json.Unmarshal(stdout.Bytes(), &contextOutput); err != nil {
		t.Fatalf("agent-context json did not decode: %v\n%s", err, stdout.String())
	}
	if contextOutput.SchemaVersion != "1" ||
		contextOutput.Available.ProfileConfig == nil ||
		contextOutput.Available.ProfileConfig.DefaultProfile != "deploy" ||
		contextOutput.Commands["exec"].Summary == "" {
		t.Fatalf("unexpected agent-context output: %+v", contextOutput)
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"profile", "list", "--json"}); code != 0 {
		t.Fatalf("profile list exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var listOutput profileListOutput
	if err := json.Unmarshal(stdout.Bytes(), &listOutput); err != nil {
		t.Fatalf("profile list json did not decode: %v\n%s", err, stdout.String())
	}
	if listOutput.DefaultProfile != "deploy" || len(listOutput.Profiles) != 2 || !listOutput.Profiles[1].Default {
		t.Fatalf("unexpected profile list output: %+v", listOutput)
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "--json"}); code != 0 {
		t.Fatalf("profile show exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var showOutput profileShowOutput
	if err := json.Unmarshal(stdout.Bytes(), &showOutput); err != nil {
		t.Fatalf("profile show json did not decode: %v\n%s", err, stdout.String())
	}
	if showOutput.Profile.Name != "deploy" || len(showOutput.Profile.Secrets) != 2 {
		t.Fatalf("unexpected profile show output: %+v", showOutput)
	}
	if strings.Contains(stdout.String()+stderr.String(), "synthetic-secret-value") {
		t.Fatalf("profile output leaked secret-looking canary")
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("agent metadata commands touched daemon manager: %+v", manager)
	}
}

func TestAppProfilesTextAndErrors(t *testing.T) {
	root := t.TempDir()
	writeProfileConfig(t, root, `
version: 1
default_profile: deploy
profiles:
  base:
    reason: Base
    secrets:
      BASE_TOKEN:
        ref: op://Example/Base/token
        account: base.1password.com
  deploy:
    include:
      - base
    account: deploy.1password.com
    reason: Deploy
    ttl: 30m
    secrets:
      DEPLOY_TOKEN: op://Example/Deploy/token
`)
	t.Chdir(root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"profile", "list"}); code != 0 {
		t.Fatalf("profile list exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{"default_profile:", "deploy", "base", "deploy (default)"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("profile list stdout = %q, want %q", stdout.String(), want)
		}
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "deploy"}); code != 0 {
		t.Fatalf("profile show exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"profile:", "deploy",
		"account:", "deploy.1password.com",
		"reason:", "Deploy",
		"ttl:", "30m",
		"include:", "base",
		"DEPLOY_TOKEN",
		"BASE_TOKEN",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("profile show stdout = %q, want %q", stdout.String(), want)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "missing"}); code != 1 {
		t.Fatalf("profile show missing exit=%d, want 1; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "valid profiles: base, deploy") {
		t.Fatalf("profile show missing stderr = %q", stderr.String())
	}

	stderr.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "--json", "missing"}); code != 1 {
		t.Fatalf("profile show missing json exit=%d, want 1; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var errOutput struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Context       string `json:"context"`
		Error         string `json:"error"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &errOutput); err != nil {
		t.Fatalf("profile error json did not decode: %v\n%s", err, stdout.String())
	}
	if errOutput.SchemaVersion != "1" || errOutput.OK || errOutput.Context != "select profile" ||
		!strings.Contains(errOutput.Error, "select profile") ||
		!strings.Contains(errOutput.Error, "valid profiles") {
		t.Fatalf("profile error json = %+v", errOutput)
	}
}

func TestAppProfileShowGCPProfileTextAndJSON(t *testing.T) {
	root := t.TempDir()
	writeProfileConfig(t, root, `
version: 1
default_profile: beta-logs
profiles:
  beta-logs:
    reason: Inspect beta logs
    ttl: 5m
    gcp:
      google_account: work
      project: fixture-beta
      service_account: agent-beta-logs@fixture-beta.iam.gserviceaccount.com
      scopes:
        - https://www.googleapis.com/auth/logging.read
        - https://www.googleapis.com/auth/cloud-platform
`)
	t.Chdir(root)
	manager := &appFakeDaemonManager{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"profile", "show"}); code != 0 {
		t.Fatalf("profile show GCP exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"gcp:",
		"google_account:",
		"work",
		"project:",
		"fixture-beta",
		"service_account:",
		"agent-beta-logs@fixture-beta.iam.gserviceaccount.com",
		"https://www.googleapis.com/auth/cloud-platform",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("profile show GCP stdout = %q, want %q", stdout.String(), want)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := app.Run(context.Background(), []string{"profile", "show", "--json", "beta-logs"}); code != 0 {
		t.Fatalf("profile show GCP json exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var output profileShowOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("profile show GCP json did not decode: %v\n%s", err, stdout.String())
	}
	if output.Profile.GCP == nil ||
		output.Profile.GCP.GoogleAccount != "work" ||
		output.Profile.GCP.Project != "fixture-beta" ||
		len(output.Profile.GCP.Scopes) != 2 {
		t.Fatalf("unexpected GCP profile json: %+v", output.Profile)
	}
	if manager.ensureCalls != 0 || manager.connectCalls != 0 {
		t.Fatalf("profile show GCP touched daemon manager: %+v", manager)
	}
}

func TestAppDaemonStatusReportsStoppedAfterRequestCancellation(t *testing.T) {
	client, requestReceived, cleanup := startStallingAppDaemon(t)
	defer cleanup()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	manager := control.NewManagerWithSocketPath(client.SocketPath)
	manager.DaemonPath = os.Args[0]
	app := newTestApp(manager, &stdout, &stderr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- app.Run(ctx, []string{"daemon", "status"})
	}()

	waitForAppDaemonRequest(t, requestReceived)
	cancel()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("daemon status exit=%d, want stopped failure; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "agent-secretd: stopped") {
			t.Fatalf("daemon status stdout = %q", stdout.String())
		}
	case <-time.After(time.Second):
		t.Fatal("daemon status did not return after request cancellation")
	}
}

func TestAppDoctorReportsFailureWithoutSecretValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "synthetic-secret-value"}},
		Audit:    &appAudit{},
	}, func(context.Context, string) error {
		return errors.New("desktop integration unavailable")
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	app.DoctorApproverCheck = func(context.Context) error { return nil }

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 1 {
		t.Fatalf("doctor exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "1password desktop integration: failed") {
		t.Fatalf("doctor stdout = %q, want 1Password failure", stdout.String())
	}
	if strings.Contains(stdout.String(), "synthetic-secret-value") || strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("doctor leaked secret: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func findDoctorCheck(checks []doctorCheck, name string) (doctorCheck, bool) {
	for _, check := range checks {
		if check.Name == name {
			return check, true
		}
	}
	return doctorCheck{}, false
}

func TestAppDaemonStartAndStopCommands(t *testing.T) {
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"daemon", "start"}); code != 0 {
		t.Fatalf("daemon start exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "running pid=") {
		t.Fatalf("daemon start output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "stop"}); code != 0 {
		t.Fatalf("daemon stop exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "agent-secretd: stopped" {
		t.Fatalf("daemon stop output = %q", stdout.String())
	}
}

func TestAppDaemonCommandsUseManagerWithoutSocket(t *testing.T) {
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(t.TempDir(), "d.sock"),
		status:     protocol.StatusPayload{PID: 4321},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"daemon", "status"}); code != 0 {
		t.Fatalf("daemon status exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "running pid=4321") {
		t.Fatalf("daemon status output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "start"}); code != 0 {
		t.Fatalf("daemon start exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "running pid=4321") {
		t.Fatalf("daemon start output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "stop"}); code != 0 {
		t.Fatalf("daemon stop exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "agent-secretd: stopped" {
		t.Fatalf("daemon stop output = %q", stdout.String())
	}
	if manager.statusCalls != 2 || manager.startCalls != 1 || manager.stopCalls != 1 {
		t.Fatalf(
			"manager calls: status=%d start=%d stop=%d",
			manager.statusCalls,
			manager.startCalls,
			manager.stopCalls,
		)
	}
}

func TestAppInstallCommands(t *testing.T) {
	t.Run("cli", func(t *testing.T) {
		var gotOptions install.CLIOptions
		runInstallCommandTest(t, []string{"install-cli", "--bin-dir", "/tmp/bin", "--force"}, func(app *App) {
			app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
				gotOptions = options
				return install.CLIResult{
					LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
				}, nil
			}
		}, "/tmp/bin/agent-secret")
		if gotOptions.BinDir != "/tmp/bin" || !gotOptions.Force {
			t.Fatalf("install-cli options = %+v", gotOptions)
		}
	})

	t.Run("skill", func(t *testing.T) {
		var gotOptions install.SkillOptions
		runInstallCommandTest(t, []string{"skill-install", "--skills-dir", "/tmp/skills", "--force"}, func(app *App) {
			app.InstallSkill = func(options install.SkillOptions) (install.SkillResult, error) {
				gotOptions = options
				return install.SkillResult{
					LinkPath:   filepath.Join(options.SkillsDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/skills/agent-secret",
				}, nil
			}
		}, "/tmp/skills/agent-secret")
		if gotOptions.SkillsDir != "/tmp/skills" || !gotOptions.Force {
			t.Fatalf("skill-install options = %+v", gotOptions)
		}
	})
}

func TestAppInstallCommandsJSON(t *testing.T) {
	t.Run("cli", func(t *testing.T) {
		runInstallCommandJSONTest(t, []string{"install-cli", "--bin-dir", "/tmp/bin", "--json"}, func(app *App) {
			app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
				return install.CLIResult{
					LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
				}, nil
			}
		}, "/tmp/bin/agent-secret")
	})

	t.Run("skill", func(t *testing.T) {
		runInstallCommandJSONTest(t, []string{"skill-install", "--skills-dir", "/tmp/skills", "--json"}, func(app *App) {
			app.InstallSkill = func(options install.SkillOptions) (install.SkillResult, error) {
				return install.SkillResult{
					LinkPath:   filepath.Join(options.SkillsDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/skills/agent-secret",
				}, nil
			}
		}, "/tmp/skills/agent-secret")
	})
}

func TestAppInstallCLIWarnsWhenCommandDirIsNotOnPath(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	t.Setenv("HOME", home)
	t.Setenv("PATH", filepath.Join(t.TempDir(), "other-bin"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(binDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 0 {
		t.Fatalf("install-cli exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "is not on PATH") {
		t.Fatalf("install-cli stdout = %q, want PATH warning", stdout.String())
	}
	wantExportLine := fmt.Sprintf("export PATH=%s:\"$PATH\"", shellSingleQuote(binDir))
	wantQuotedLine := shellSingleQuote(wantExportLine)
	wantOneLiner := fmt.Sprintf(
		"grep -qxF %s \"$HOME/.zprofile\" 2>/dev/null || printf '\\n%%s\\n' %s >> \"$HOME/.zprofile\"; exec zsh -l",
		wantQuotedLine,
		wantQuotedLine,
	)
	if !strings.Contains(stdout.String(), wantOneLiner) {
		t.Fatalf("install-cli stdout = %q, want zsh setup one-liner %q", stdout.String(), wantOneLiner)
	}
}

func TestAppInstallCLIWarnsWhenEarlierPathEntryShadowsCommand(t *testing.T) {
	staleBinDir := t.TempDir()
	binDir := filepath.Join(t.TempDir(), "bin")
	writeExecutable(t, staleBinDir, "agent-secret")
	t.Setenv("PATH", strings.Join([]string{staleBinDir, binDir}, string(os.PathListSeparator)))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(binDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 0 {
		t.Fatalf("install-cli exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "An earlier PATH entry contains agent-secret") ||
		!strings.Contains(stdout.String(), filepath.Join(staleBinDir, "agent-secret")) {
		t.Fatalf("install-cli stdout = %q, want shadowing warning", stdout.String())
	}
}

func TestAppInstallCLIJSONReportsShadowedCommand(t *testing.T) {
	staleBinDir := t.TempDir()
	binDir := filepath.Join(t.TempDir(), "bin")
	writeExecutable(t, staleBinDir, "agent-secret")
	t.Setenv("PATH", strings.Join([]string{staleBinDir, binDir}, string(os.PathListSeparator)))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(binDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir, "--json"})
	if code != 0 {
		t.Fatalf("install-cli exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var output installOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("decode install output: %v", err)
	}
	if output.PathWarning == nil || output.PathWarning.ShadowedBy != filepath.Join(staleBinDir, "agent-secret") {
		t.Fatalf("path warning = %+v, want shadowed command", output.PathWarning)
	}
}

func TestAppInstallCLISkipsPathWarningWhenCommandDirIsOnPath(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	t.Setenv("PATH", strings.Join([]string{filepath.Join(t.TempDir(), "other-bin"), binDir}, string(os.PathListSeparator)))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(binDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 0 {
		t.Fatalf("install-cli exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "is not on PATH") {
		t.Fatalf("install-cli stdout = %q, did not expect PATH warning", stdout.String())
	}
}

func TestAppSkipsDaemonManagerForNonDaemonCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	managerCalls := 0
	app := NewApp(func() (control.Manager, error) {
		managerCalls++
		return control.Manager{}, errors.New("daemon manager should not initialize")
	}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}
	app.InstallSkill = func(options install.SkillOptions) (install.SkillResult, error) {
		return install.SkillResult{
			LinkPath:   filepath.Join(options.SkillsDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/skills/agent-secret",
		}, nil
	}

	for _, args := range [][]string{
		{"help"},
		{"skill-install", "--skills-dir", filepath.Join(t.TempDir(), "skills"), "--force"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := app.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d stderr=%q stdout=%q", args, code, stderr.String(), stdout.String())
		}
	}
	if managerCalls != 0 {
		t.Fatalf("daemon manager factory called %d times for non-daemon commands", managerCalls)
	}
}

func TestAppInstallCLIAttemptsBackgroundHelperRepair(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	manager := &appFakeDaemonManager{
		repairResult: control.RepairResult{
			Status: control.RepairStatusRefreshed,
			PID:    5678,
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 0 {
		t.Fatalf("install-cli exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if manager.repairCalls != 1 {
		t.Fatalf("repair calls = %d, want 1", manager.repairCalls)
	}
	if !strings.Contains(stderr.String(), "Activating Agent Secret local service") {
		t.Fatalf("install-cli stderr = %q, want local service activation status", stderr.String())
	}
}

func TestAppInstallCLIFailsWhenLocalServiceActivationFails(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	manager := &appFakeDaemonManager{
		repairErr: fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 1 {
		t.Fatalf("install-cli exit=%d, want 1; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if manager.repairCalls != 1 {
		t.Fatalf("repair calls = %d, want 1", manager.repairCalls)
	}
	if !strings.Contains(stderr.String(), "unexpected local service") ||
		!strings.Contains(stderr.String(), "Details: unexpected background helper: untrusted peer") ||
		!strings.Contains(stderr.String(), "agent-secret install-cli --force") {
		t.Fatalf("install-cli stderr = %q, want activation failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("install-cli stdout = %q, want empty on activation failure", stdout.String())
	}
}

func TestAppInstallCLIFailsWhenBackgroundHelperManagerCannotInitialize(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	managerErr := errors.New("manager unavailable")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(func() (control.Manager, error) {
		return control.Manager{}, managerErr
	}, &stdout, &stderr)
	app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
		return install.CLIResult{
			LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
			TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
		}, nil
	}

	code := app.Run(context.Background(), []string{"install-cli", "--bin-dir", binDir})
	if code != 1 {
		t.Fatalf("install-cli exit=%d, want 1; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "activate Agent Secret local service") ||
		!strings.Contains(stderr.String(), managerErr.Error()) {
		t.Fatalf("install-cli stderr = %q, want manager activation error", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("install-cli stdout = %q, want empty on activation failure", stdout.String())
	}
}

func runInstallCommandTest(t *testing.T, args []string, configure func(*App), stdoutWant string) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	configure(&app)

	code := app.Run(context.Background(), args)
	if code != 0 {
		t.Fatalf("%v exit=%d stderr=%q stdout=%q", args, code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), stdoutWant) {
		t.Fatalf("%v stdout = %q, want %q", args, stdout.String(), stdoutWant)
	}
}

func runInstallCommandJSONTest(t *testing.T, args []string, configure func(*App), linkPath string) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(&appFakeDaemonManager{}, &stdout, &stderr)
	configure(&app)

	if code := app.Run(context.Background(), args); code != 0 {
		t.Fatalf("%v exit=%d stderr=%q stdout=%q", args, code, stderr.String(), stdout.String())
	}
	var output installOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatalf("%v json did not decode: %v\n%s", args, err, stdout.String())
	}
	if !output.Installed || output.LinkPath != linkPath {
		t.Fatalf("%v json = %+v", args, output)
	}
}

func TestAppReportsParseErrorsAndStoppedDaemonStatus(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(
		control.NewManagerWithSocketPath(filepath.Join(t.TempDir(), "missing.sock")),
		&stdout,
		&stderr,
	)

	if code := app.Run(context.Background(), []string{"bananas"}); code != 2 {
		t.Fatalf("unknown command exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("parse error stderr = %q", stderr.String())
	}

	stderr.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "status"}); code != 1 {
		t.Fatalf("stopped daemon status exit=%d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "agent-secretd: stopped") {
		t.Fatalf("stopped daemon status stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stopped daemon status wrote stderr: %q", stderr.String())
	}
}

func TestAppDoctorUsesManagerWithoutSocket(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		status:     protocol.StatusPayload{PID: 5678},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 0 {
		t.Fatalf("doctor exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	for _, want := range []string{
		"command symlink: not installed",
		"Agent Secret local service: ok pid=5678",
		"socket directory: private",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor output = %q, want %q", stdout.String(), want)
		}
	}
	if manager.repairCalls != 1 || manager.statusCalls != 0 {
		t.Fatalf("manager calls: repair=%d status=%d", manager.repairCalls, manager.statusCalls)
	}
}

func TestAppDoctorReportsRefreshedBackgroundHelper(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		repairResult: control.RepairResult{
			Status: control.RepairStatusRefreshed,
			PID:    5678,
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 0 {
		t.Fatalf("doctor exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "Agent Secret local service: refreshed pid=5678") {
		t.Fatalf("doctor output = %q, want refreshed local service", stdout.String())
	}
	if manager.repairCalls != 1 {
		t.Fatalf("manager repair calls = %d, want 1", manager.repairCalls)
	}
}

func TestAppDoctorReportsStaleCommandSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	staleHelper := "/Applications/Agent Secret.app/Contents/Library/Helpers/AgentSecretDaemon.app/Contents/MacOS/Agent Secret"
	if err := os.Symlink(staleHelper, filepath.Join(binDir, "agent-secret")); err != nil {
		t.Fatalf("create stale command symlink: %v", err)
	}
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		status:     protocol.StatusPayload{PID: 5678},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor", "--json"})
	if code != 1 {
		t.Fatalf("doctor exit=%d, want 1; stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var got doctorOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode doctor json: %v; stdout=%q", err, stdout.String())
	}
	check, found := findDoctorCheck(got.Checks, "command_symlink")
	if !found {
		t.Fatalf("doctor checks missing command_symlink: %+v", got.Checks)
	}
	if check.Status != "failed" ||
		!strings.Contains(check.Error, staleHelper) ||
		!strings.Contains(check.Error, "agent-secret install-cli --force") {
		t.Fatalf("command symlink check = %+v", check)
	}
}

func TestAppDoctorReportsRepairRequiredBackgroundHelper(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		repairErr:  fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor", "--json"})
	if code != 1 {
		t.Fatalf("doctor exit=%d, want 1", code)
	}
	var got doctorOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode doctor json: %v; stdout=%q", err, stdout.String())
	}
	if got.OK {
		t.Fatalf("doctor json ok = true, want false: %+v", got)
	}
	found := false
	for _, check := range got.Checks {
		if check.Name == "local_service" {
			found = true
			if check.Status != string(control.RepairStatusRepairRequired) ||
				!strings.Contains(check.Error, "untrusted peer") {
				t.Fatalf("local service check = %+v", check)
			}
		}
	}
	if !found {
		t.Fatalf("doctor checks missing local service: %+v", got.Checks)
	}
	if stderr.Len() != 0 {
		t.Fatalf("doctor stderr = %q, want empty", stderr.String())
	}
}

func TestAppDoctorReportsRepairRequiredBackgroundHelperText(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		repairErr:  fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 1 {
		t.Fatalf("doctor exit=%d, want 1", code)
	}
	for _, want := range []string{
		"Agent Secret local service: activation required",
		"Run `agent-secret install-cli --force`",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor output = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("doctor stderr = %q, want empty", stderr.String())
	}
}

func TestAppRepairReportsRefreshedBackgroundHelper(t *testing.T) {
	manager := &appFakeDaemonManager{
		repairResult: control.RepairResult{
			Status: control.RepairStatusRefreshed,
			PID:    5678,
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{"repair"})
	if code != 0 {
		t.Fatalf("repair exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "Background helper: refreshed" {
		t.Fatalf("repair stdout = %q", stdout.String())
	}
	if manager.repairCalls != 1 || manager.connectCalls != 0 {
		t.Fatalf("manager calls: repair=%d connect=%d", manager.repairCalls, manager.connectCalls)
	}
}

func TestAppRepairJSONReportsBackgroundHelperStatus(t *testing.T) {
	manager := &appFakeDaemonManager{
		repairResult: control.RepairResult{
			Status: control.RepairStatusOK,
			PID:    5678,
		},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{"repair", "--json"})
	if code != 0 {
		t.Fatalf("repair exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var got repairOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode repair json: %v; stdout=%q", err, stdout.String())
	}
	if got.SchemaVersion != "1" || got.Status != string(control.RepairStatusOK) || got.PID != 5678 {
		t.Fatalf("repair json = %+v", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("repair stderr = %q, want empty", stderr.String())
	}
}

func TestAppRepairJSONReportsWriteFailure(t *testing.T) {
	manager := &appFakeDaemonManager{
		repairResult: control.RepairResult{
			Status: control.RepairStatusOK,
			PID:    5678,
		},
	}
	writeErr := errors.New("stdout closed")
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, failingWriter{err: writeErr}, &stderr)

	code := app.Run(context.Background(), []string{"repair", "--json"})
	if code != 1 {
		t.Fatalf("repair exit=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "write repair json") ||
		!strings.Contains(stderr.String(), writeErr.Error()) {
		t.Fatalf("repair stderr = %q, want write failure", stderr.String())
	}
}

func TestAppRepairReportsRepairRequired(t *testing.T) {
	manager := &appFakeDaemonManager{
		repairErr: fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{"repair"})
	if code != 1 {
		t.Fatalf("repair exit=%d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "Background helper: repair required") {
		t.Fatalf("repair stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("repair stderr = %q, want empty", stderr.String())
	}
}

func TestAppRepairJSONReportsRepairRequired(t *testing.T) {
	manager := &appFakeDaemonManager{
		repairErr: fmt.Errorf("%w: untrusted peer", control.ErrUnexpectedHelper),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)

	code := app.Run(context.Background(), []string{"repair", "--json"})
	if code != 1 {
		t.Fatalf("repair exit=%d, want 1", code)
	}
	var got repairOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode repair json: %v; stdout=%q", err, stdout.String())
	}
	if got.SchemaVersion != "1" ||
		got.Status != string(control.RepairStatusRepairRequired) ||
		!strings.Contains(got.Error, "untrusted peer") {
		t.Fatalf("repair json = %+v", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("repair stderr = %q, want empty", stderr.String())
	}
}

func TestAppDoctorUsesProjectConfigAccount(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	t.Chdir(root)
	writeProfileConfig(t, root, `
version: 1
account: fixture.1password.com
`)
	socketDir := t.TempDir()
	//nolint:gosec // G302: daemon socket directories must be private but executable by their owner.
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatalf("chmod socket dir: %v", err)
	}
	manager := &appFakeDaemonManager{
		socketPath: filepath.Join(socketDir, "d.sock"),
		status:     protocol.StatusPayload{PID: 5678},
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestAppWithDaemonManager(manager, &stdout, &stderr)
	app.DoctorApproverCheck = nil

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 0 {
		t.Fatalf("doctor exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "1password account: fixture.1password.com") {
		t.Fatalf("doctor output = %q, want project account", stdout.String())
	}
	if len(manager.checkedAccounts) != 1 || manager.checkedAccounts[0] != "fixture.1password.com" {
		t.Fatalf("checked accounts = %v, want fixture.1password.com", manager.checkedAccounts)
	}
}

func TestAppExecReportsBackgroundHelperFailureBeforeSpawn(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(
		control.NewManagerWithSocketPath(filepath.Join(t.TempDir(), "missing.sock")),
		&stdout,
		&stderr,
	)

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecReportsBackgroundHelperFailureBeforeSpawn", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "activate Agent Secret local service") {
		t.Fatalf("stderr = %q, want local service activation failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no child output", stdout.String())
	}
}

func TestAppExecReportsRandomIDFailureBeforeRequest(t *testing.T) {
	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemonbroker.Options{
		Approver: &appApprover{decision: approval.Decision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()

	entropyErr := errors.New("entropy unavailable")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(appTestManager(client), &stdout, &stderr)
	app.RandomReader = failingRandomReader{err: entropyErr}
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--allow-mutable-executable",
		"--reason", "Run helper",
		"--account", "Work",
		"--secret", "TOKEN=" + ref,
		"--",
		os.Args[0], "-test.run=TestAppExecReportsRandomIDFailureBeforeRequest", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "generate request id") || !strings.Contains(stderr.String(), entropyErr.Error()) {
		t.Fatalf("stderr = %q, want random id failure", stderr.String())
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no child output", stdout.String())
	}
}

func TestNewAppDefaultsWritersAndHelpRun(t *testing.T) {
	app := NewApp(nil, nil, nil)
	if app.Stdout == nil || app.Stderr == nil {
		t.Fatalf("NewApp did not install default writers: %+v", app)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Stdout = &stdout
	app.Stderr = &stderr
	if code := app.Run(context.Background(), []string{"help"}); code != 0 {
		t.Fatalf("help exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agent-secret controls") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

func TestDaemonAuditReporterFatalStartedAuditClassification(t *testing.T) {
	protocolErr := &control.ProtocolError{Code: protocol.ErrorCodeInvalidNonce, Message: "bad nonce"}
	if !isFatalCommandStartedAuditFailure(protocolErr) {
		t.Fatal("invalid nonce protocol error was not classified as fatal")
	}
	auditErr := &control.ProtocolError{Code: protocol.ErrorCodeAuditFailed, Message: "audit failed"}
	if !isFatalCommandStartedAuditFailure(auditErr) {
		t.Fatal("audit_failed protocol error was not classified as fatal")
	}
	stoppedErr := &control.ProtocolError{Code: protocol.ErrorCodeDaemonStopped, Message: "daemon stopped"}
	if isFatalCommandStartedAuditFailure(stoppedErr) {
		t.Fatal("daemon stopped protocol error was classified as fatal")
	}
	if !isFatalCommandStartedAuditFailure(protocol.ErrMalformedEnvelope) {
		t.Fatal("local malformed response error was not classified as fatal")
	}
	if isFatalCommandStartedAuditFailure(errors.New("network closed")) {
		t.Fatal("plain error was classified as fatal")
	}
}

func TestDaemonAuditReporterWarnsOnDaemonStoppedAfterChildStart(t *testing.T) {
	client, _, cleanup := startPostStartStoppedAppDaemon(t)
	defer cleanup()

	daemonClient, err := control.ConnectWithPeerValidator(context.Background(), client.SocketPath, nil)
	if err != nil {
		t.Fatalf("ConnectWithPeerValidator returned error: %v", err)
	}
	defer func() { _ = daemonClient.Close() }()

	var stderr bytes.Buffer
	reporter := daemonAuditReporter{
		client: daemonClient,
		correlation: protocol.Correlation{
			RequestID: "req_1",
			Nonce:     "nonce_1",
		},
		stderr: &stderr,
	}
	if err := reporter.CommandStarted(context.Background(), os.Getpid()); err != nil {
		t.Fatalf("CommandStarted returned error: %v", err)
	}
	if !strings.Contains(stderr.String(), "command_started audit was not recorded") {
		t.Fatalf("stderr = %q, want command_started warning", stderr.String())
	}
}

func runAppExecHelper() {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "child" {
		return
	}
	if os.Getenv("TOKEN") != "synthetic-secret-value" {
		fmt.Println("env-missing")
		os.Exit(42)
	}
	if expectedPlain := os.Getenv("AGENT_SECRET_APP_EXPECT_PLAIN"); expectedPlain != "" {
		if os.Getenv("PLAIN_ENV") != expectedPlain {
			fmt.Println("plain-env-missing")
			os.Exit(43)
		}
	}
	fmt.Println("env-ok")
	os.Exit(0)
}

func runAppGCPHelper() {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "child" {
		return
	}
	if os.Getenv("CLOUDSDK_CORE_PROJECT") != "fixture-beta" {
		fmt.Println("project-missing")
		os.Exit(44)
	}
	if os.Getenv("CLOUDSDK_CONFIG") == "/ambient/config" {
		fmt.Println("ambient-config-leaked")
		os.Exit(45)
	}
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" {
		fmt.Println("ambient-adc-leaked")
		os.Exit(46)
	}
	if os.Getenv("CLOUDSDK_AUTH_ACCESS_TOKEN_FILE") == "" {
		fmt.Println("token-file-missing")
		os.Exit(47)
	}
	fmt.Println("gcp-env-ok")
	os.Exit(0)
}

type appTestClient struct {
	SocketPath string
}

type appFakeDaemonManager struct {
	socketPath string
	client     daemonClient
	clients    []daemonClient
	status     protocol.StatusPayload

	repairResult control.RepairResult
	ensureErr    error
	repairErr    error
	connectErr   error
	statusErr    error
	startErr     error
	stopErr      error
	checkErr     error

	ensureCalls  int
	repairCalls  int
	connectCalls int
	statusCalls  int
	startCalls   int
	stopCalls    int
	checkCalls   int

	checkedAccounts []string
}

func (m *appFakeDaemonManager) EnsureRunning(context.Context) error {
	m.ensureCalls++
	return m.ensureErr
}

func (m *appFakeDaemonManager) Repair(context.Context) (control.RepairResult, error) {
	m.repairCalls++
	m.ensureCalls++
	if m.repairErr != nil {
		return control.RepairResult{Status: control.RepairStatusRepairRequired}, m.repairErr
	}
	if m.repairResult.Status != "" {
		return m.repairResult, nil
	}
	return control.RepairResult{Status: control.RepairStatusOK, PID: m.status.PID}, nil
}

func (m *appFakeDaemonManager) Connect(context.Context) (daemonClient, error) {
	m.connectCalls++
	if m.connectErr != nil {
		return nil, m.connectErr
	}
	if len(m.clients) > 0 {
		client := m.clients[0]
		m.clients = m.clients[1:]
		return client, nil
	}
	if m.client == nil {
		return nil, errors.New("fake daemon client missing")
	}
	return m.client, nil
}

func (m *appFakeDaemonManager) Status(context.Context) (protocol.StatusPayload, error) {
	m.statusCalls++
	return m.status, m.statusErr
}

func (m *appFakeDaemonManager) Start(context.Context) error {
	m.startCalls++
	return m.startErr
}

func (m *appFakeDaemonManager) Stop(context.Context) error {
	m.stopCalls++
	return m.stopErr
}

func (m *appFakeDaemonManager) CheckOnePassword(_ context.Context, account string) error {
	m.checkCalls++
	m.checkedAccounts = append(m.checkedAccounts, account)
	return m.checkErr
}

func (m *appFakeDaemonManager) SocketPath() string {
	return m.socketPath
}

type appFakeDaemonClient struct {
	execPayload              protocol.ExecResponsePayload
	itemDescribePayload      protocol.ItemDescribeResponsePayload
	sessionCreatePayload     protocol.SessionCreateResponsePayload
	sessionResolvePayload    protocol.SessionResolveResponsePayload
	sessionDestroyPayload    protocol.SessionDestroyResponsePayload
	sessionListPayload       protocol.SessionListResponsePayload
	gcpCommandPayload        protocol.GCPCommandResponsePayload
	gcpAuthStatusPayload     protocol.GCPAuthStatusResponsePayload
	gcpAuthLoginPayload      protocol.GCPAuthLoginResponsePayload
	gcpAuthLogoutPayload     protocol.GCPAuthLogoutResponsePayload
	gcpSessionCreatePayload  protocol.GCPSessionCreateResponsePayload
	gcpSessionListPayload    protocol.GCPSessionListResponsePayload
	gcpSessionDestroyPayload protocol.GCPSessionDestroyResponsePayload

	requestErr         error
	gcpErr             error
	gcpAuthErr         error
	itemDescribeErr    error
	sessionCreateErr   error
	sessionResolveErr  error
	sessionDestroyErr  error
	sessionListErr     error
	reportStartedErr   error
	reportCompletedErr error
	closeErr           error

	requestExecCalls         int
	itemDescribeCalls        int
	sessionCreateCalls       int
	sessionResolveCalls      int
	sessionDestroyCalls      int
	sessionListCalls         int
	requestGCPExecCalls      int
	gcpAuthStatusCalls       int
	gcpAuthLoginCalls        int
	gcpAuthLogoutCalls       int
	createGCPSessionCalls    int
	listGCPSessionsCalls     int
	destroyGCPSessionCalls   int
	useGCPSessionCalls       int
	requests                 []request.ExecRequest
	itemDescribeRequests     []request.ItemDescribeRequest
	sessionCreateRequests    []request.SessionCreateRequest
	sessionResolveRequests   []request.SessionResolveRequest
	sessionDestroyRequests   []request.SessionDestroyRequest
	gcpExecRequests          []request.GCPExecRequest
	gcpAuthStatusRequests    []request.GCPAuthStatusRequest
	gcpAuthLoginRequests     []request.GCPAuthLoginRequest
	gcpAuthLogoutRequests    []request.GCPAuthLogoutRequest
	gcpSessionCreateRequests []request.GCPSessionCreateRequest
	gcpSessionUseRequests    []request.GCPSessionUseRequest
	closeCalls               int
	startedPIDs              []int
	completedExitCodes       []int
}

func (c *appFakeDaemonClient) Close() error {
	c.closeCalls++
	return c.closeErr
}

func (c *appFakeDaemonClient) RequestExec(
	_ context.Context,
	_ protocol.Correlation,
	req request.ExecRequest,
) (protocol.ExecResponsePayload, error) {
	c.requestExecCalls++
	c.requests = append(c.requests, req)
	return c.execPayload, c.requestErr
}

func (c *appFakeDaemonClient) RequestGCPExec(
	_ context.Context,
	_ protocol.Correlation,
	req request.GCPExecRequest,
) (protocol.GCPCommandResponsePayload, error) {
	c.requestGCPExecCalls++
	c.gcpExecRequests = append(c.gcpExecRequests, req)
	return c.gcpCommandPayload, c.gcpErr
}

func (c *appFakeDaemonClient) GCPAuthStatus(
	_ context.Context,
	req request.GCPAuthStatusRequest,
) (protocol.GCPAuthStatusResponsePayload, error) {
	c.gcpAuthStatusCalls++
	c.gcpAuthStatusRequests = append(c.gcpAuthStatusRequests, req)
	return c.gcpAuthStatusPayload, c.gcpAuthErr
}

func (c *appFakeDaemonClient) GCPAuthLogin(
	_ context.Context,
	req request.GCPAuthLoginRequest,
) (protocol.GCPAuthLoginResponsePayload, error) {
	c.gcpAuthLoginCalls++
	c.gcpAuthLoginRequests = append(c.gcpAuthLoginRequests, req)
	return c.gcpAuthLoginPayload, c.gcpAuthErr
}

func (c *appFakeDaemonClient) GCPAuthLogout(
	_ context.Context,
	req request.GCPAuthLogoutRequest,
) (protocol.GCPAuthLogoutResponsePayload, error) {
	c.gcpAuthLogoutCalls++
	c.gcpAuthLogoutRequests = append(c.gcpAuthLogoutRequests, req)
	return c.gcpAuthLogoutPayload, c.gcpAuthErr
}

func (c *appFakeDaemonClient) CreateGCPSession(
	_ context.Context,
	_ protocol.Correlation,
	req request.GCPSessionCreateRequest,
	_ string,
) (protocol.GCPSessionCreateResponsePayload, error) {
	c.createGCPSessionCalls++
	c.gcpSessionCreateRequests = append(c.gcpSessionCreateRequests, req)
	return c.gcpSessionCreatePayload, c.gcpErr
}

func (c *appFakeDaemonClient) ListGCPSessions(
	_ context.Context,
	_ string,
) (protocol.GCPSessionListResponsePayload, error) {
	c.listGCPSessionsCalls++
	return c.gcpSessionListPayload, c.gcpErr
}

func (c *appFakeDaemonClient) DestroyGCPSession(
	_ context.Context,
	_ request.GCPSessionDestroyRequest,
) (protocol.GCPSessionDestroyResponsePayload, error) {
	c.destroyGCPSessionCalls++
	return c.gcpSessionDestroyPayload, c.gcpErr
}

func (c *appFakeDaemonClient) UseGCPSession(
	_ context.Context,
	_ protocol.Correlation,
	req request.GCPSessionUseRequest,
) (protocol.GCPCommandResponsePayload, error) {
	c.useGCPSessionCalls++
	c.gcpSessionUseRequests = append(c.gcpSessionUseRequests, req)
	return c.gcpCommandPayload, c.gcpErr
}

func (c *appFakeDaemonClient) DescribeItem(
	_ context.Context,
	_ protocol.Correlation,
	req request.ItemDescribeRequest,
) (protocol.ItemDescribeResponsePayload, error) {
	c.itemDescribeCalls++
	c.itemDescribeRequests = append(c.itemDescribeRequests, req)
	return c.itemDescribePayload, c.itemDescribeErr
}

func (c *appFakeDaemonClient) CreateSession(
	_ context.Context,
	_ protocol.Correlation,
	req request.SessionCreateRequest,
) (protocol.SessionCreateResponsePayload, error) {
	c.sessionCreateCalls++
	c.sessionCreateRequests = append(c.sessionCreateRequests, req)
	return c.sessionCreatePayload, c.sessionCreateErr
}

func (c *appFakeDaemonClient) ResolveSession(
	_ context.Context,
	_ protocol.Correlation,
	req request.SessionResolveRequest,
) (protocol.SessionResolveResponsePayload, error) {
	c.sessionResolveCalls++
	c.sessionResolveRequests = append(c.sessionResolveRequests, req)
	return c.sessionResolvePayload, c.sessionResolveErr
}

func (c *appFakeDaemonClient) DestroySession(
	_ context.Context,
	req request.SessionDestroyRequest,
) (protocol.SessionDestroyResponsePayload, error) {
	c.sessionDestroyCalls++
	c.sessionDestroyRequests = append(c.sessionDestroyRequests, req)
	return c.sessionDestroyPayload, c.sessionDestroyErr
}

func (c *appFakeDaemonClient) ListSessions(_ context.Context) (protocol.SessionListResponsePayload, error) {
	c.sessionListCalls++
	return c.sessionListPayload, c.sessionListErr
}

func (c *appFakeDaemonClient) ReportStarted(_ context.Context, _ protocol.Correlation, childPID int) error {
	c.startedPIDs = append(c.startedPIDs, childPID)
	return c.reportStartedErr
}

func (c *appFakeDaemonClient) ReportCompleted(
	_ context.Context,
	_ protocol.Correlation,
	exitCode int,
	_ string,
) error {
	c.completedExitCodes = append(c.completedExitCodes, exitCode)
	return c.reportCompletedErr
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func appTestManager(client appTestClient) control.Manager {
	manager := control.NewManagerWithSocketPath(client.SocketPath)
	manager.DaemonPath = os.Args[0]
	return manager
}

type appApprover struct {
	decision approval.Decision
}

func (a *appApprover) Approve(
	_ context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	return a.decision, nil
}

type appResolver struct {
	values map[string]string
}

func (r *appResolver) Resolve(_ context.Context, secret request.Secret) (string, error) {
	return r.values[secret.Ref.Raw], nil
}

func (r *appResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return itemmetadata.Metadata{
		Account: account,
		Vault:   ref.Vault,
		Item:    ref.Item,
		Fields: []itemmetadata.Field{
			{
				Label:     "token",
				Type:      "Concealed",
				Concealed: true,
				Ref:       itemmetadata.BuildFieldRef(ref.Vault, ref.Item, "", "token"),
				Alias:     "TOKEN",
			},
		},
	}, nil
}

type fakeBitwardenStore struct {
	tokens          map[string]bwsm.Token
	interactivePuts int
	getErr          error
	putErr          error
	deleteErr       error
}

func (s *fakeBitwardenStore) Get(_ context.Context, alias string) (bwsm.Token, bool, error) {
	if s.getErr != nil {
		return bwsm.Token{}, false, s.getErr
	}
	token, ok := s.tokens[alias]
	return token, ok, nil
}

func (s *fakeBitwardenStore) Put(_ context.Context, token bwsm.Token) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.tokens[token.Alias] = token
	return nil
}

func (s *fakeBitwardenStore) PutAllowingUserInteraction(_ context.Context, token bwsm.Token) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.interactivePuts++
	s.tokens[token.Alias] = token
	return nil
}

func (s *fakeBitwardenStore) Delete(_ context.Context, alias string) (bool, error) {
	if s.deleteErr != nil {
		return false, s.deleteErr
	}
	if _, ok := s.tokens[alias]; !ok {
		return false, nil
	}
	delete(s.tokens, alias)
	return true, nil
}

func (s *fakeBitwardenStore) List(context.Context) ([]bwsm.Token, error) {
	tokens := make([]bwsm.Token, 0, len(s.tokens))
	for _, token := range s.tokens {
		tokens = append(tokens, token)
	}
	return tokens, nil
}

type appAudit struct{}

func (a *appAudit) Record(_ context.Context, _ audit.Event) error {
	return nil
}

func (a *appAudit) Preflight(context.Context) error {
	return nil
}

type failingRandomReader struct {
	err error
}

func (r failingRandomReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type failingWriter struct {
	err error
}

func (f failingWriter) Write(_ []byte) (int, error) {
	return 0, f.err
}

type appAllowPeer struct{}

func (appAllowPeer) Info(conn *net.UnixConn) (peercred.Info, error) {
	return peercred.Inspect(conn)
}

func (appAllowPeer) Validate(_ *net.UnixConn) error {
	return nil
}

type appSessionPeerAuthorizer struct{}

func (appSessionPeerAuthorizer) BindSessionPeer(
	peer peercred.Info,
	policy request.SessionBindingPolicy,
) (daemonbroker.SessionPeerBinding, error) {
	return daemonbroker.SessionPeerBinding{
		CreatorPeer: peer,
		Anchor: peercred.ProcessIdentity{
			UID:            peer.UID,
			GID:            peer.GID,
			PID:            peer.PID,
			ExecutablePath: peer.ExecutablePath,
			StartTime:      time.Unix(1, 0).UTC(),
		},
		Policy: policy,
	}, nil
}

func (appSessionPeerAuthorizer) ValidateSessionPeer(daemonbroker.SessionPeerBinding, peercred.Info) error {
	return nil
}

func startAppTestServer(
	t *testing.T,
	opts daemonbroker.Options,
	onePasswordChecks ...func(context.Context, string) error,
) (appTestClient, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-app-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	if opts.SessionPeerAuthorizer == nil {
		opts.SessionPeerAuthorizer = appSessionPeerAuthorizer{}
	}
	broker, err := daemonbroker.New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	onePasswordCheck := func(context.Context, string) error { return nil }
	if len(onePasswordChecks) > 0 {
		onePasswordCheck = onePasswordChecks[0]
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:           broker,
		Validator:        appAllowPeer{},
		ClientValidator:  peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
		OnePasswordCheck: onePasswordCheck,
	})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	return appTestClient{SocketPath: path}, func() {
		cancel()
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
}

func currentExecutableClientPaths(t *testing.T) []string {
	t.Helper()
	paths, err := peertrust.CurrentExecutableClientPaths()
	if err != nil {
		t.Fatalf("CurrentExecutableClientPaths returned error: %v", err)
	}
	return paths
}

func startPostStartStoppedAppDaemon(t *testing.T) (appTestClient, <-chan protocol.MessageType, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-app-post-start-stop-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	errs := make(chan error, 1)
	events := make(chan protocol.MessageType, 8)
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					reportPostStartStoppedDaemonError(errs, err)
					return
				}
			}
			go func() {
				if err := handlePostStartStoppedDaemonConn(conn, events); err != nil {
					reportPostStartStoppedDaemonError(errs, err)
				}
			}()
		}
	}()

	return appTestClient{SocketPath: path}, events, func() {
		cancel()
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
		select {
		case err := <-errs:
			t.Fatalf("post-start stopped daemon returned error: %v", err)
		default:
		}
	}
}

func postStartStoppedDaemonSaw(events <-chan protocol.MessageType, want protocol.MessageType) bool {
	for {
		select {
		case got := <-events:
			if got == want {
				return true
			}
		default:
			return false
		}
	}
}

func reportPostStartStoppedDaemonError(errs chan<- error, err error) {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	select {
	case errs <- err:
	default:
	}
}

func handlePostStartStoppedDaemonConn(conn *net.UnixConn, events chan<- protocol.MessageType) error {
	defer func() { _ = conn.Close() }()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	for {
		var env protocol.Envelope
		if err := decoder.Decode(&env); err != nil {
			return err
		}
		select {
		case events <- env.Type:
		default:
		}
		switch env.Type {
		case protocol.TypeHelperHello:
			if err := writePostStartStoppedDaemonOK(encoder, env.RequestID, env.Nonce, helperidentity.Current()); err != nil {
				return err
			}
		case protocol.TypeDaemonStatus:
			if err := writePostStartStoppedDaemonOK(encoder, env.RequestID, env.Nonce, protocol.StatusPayload{PID: os.Getpid()}); err != nil {
				return err
			}
		case protocol.TypeOnePasswordStatus:
			if err := writePostStartStoppedDaemonOK(encoder, env.RequestID, env.Nonce, nil); err != nil {
				return err
			}
		case protocol.TypeRequestExec:
			payload := protocol.ExecResponsePayload{
				Env:           map[string]string{"TOKEN": "synthetic-secret-value"},
				SecretAliases: []string{"TOKEN"},
			}
			if err := writePostStartStoppedDaemonOK(encoder, env.RequestID, env.Nonce, payload); err != nil {
				return err
			}
		case protocol.TypeItemDescribe,
			protocol.TypeSessionCreate,
			protocol.TypeSessionResolve,
			protocol.TypeSessionDestroy,
			protocol.TypeSessionList,
			protocol.TypeGCPAuthStatus,
			protocol.TypeGCPAuthLogin,
			protocol.TypeGCPAuthLogout,
			protocol.TypeGCPExec,
			protocol.TypeGCPSessionCreate,
			protocol.TypeGCPSessionList,
			protocol.TypeGCPSessionDestroy,
			protocol.TypeGCPWithSession,
			protocol.TypeCommandStarted,
			protocol.TypeCommandCompleted:
			if err := writePostStartStoppedDaemonError(encoder, env.RequestID, env.Nonce, protocol.ErrorCodeDaemonStopped, daemonbroker.ErrDaemonStopped); err != nil {
				return err
			}
		case protocol.TypeDaemonStop,
			protocol.TypeApprovalPending,
			protocol.TypeApprovalDecision,
			protocol.TypeOK,
			protocol.TypeError:
			if err := writePostStartStoppedDaemonError(encoder, env.RequestID, env.Nonce, protocol.ErrorCodeBadType, protocol.ErrProtocolType); err != nil {
				return err
			}
		default:
			if err := writePostStartStoppedDaemonError(encoder, env.RequestID, env.Nonce, protocol.ErrorCodeBadType, protocol.ErrProtocolType); err != nil {
				return err
			}
		}
	}
}

func writePostStartStoppedDaemonOK(encoder *json.Encoder, requestID string, nonce string, payload any) error {
	env, err := protocol.NewEnvelope(protocol.TypeOK, protocol.Correlation{RequestID: requestID, Nonce: nonce}, payload)
	if err != nil {
		return err
	}
	return encoder.Encode(env)
}

func writePostStartStoppedDaemonError(encoder *json.Encoder, requestID string, nonce string, code protocol.ErrorCode, err error) error {
	payload := protocol.ErrorPayload{Code: code, Message: err.Error()}
	env, marshalErr := protocol.NewEnvelope(protocol.TypeError, protocol.Correlation{RequestID: requestID, Nonce: nonce}, payload)
	if marshalErr != nil {
		return marshalErr
	}
	return encoder.Encode(env)
}

func startStallingAppDaemon(t *testing.T) (appTestClient, <-chan struct{}, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-app-stall-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	release := make(chan struct{})
	requestReceived := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fscan(conn)
		close(requestReceived)
		<-release
		done <- nil
	}()

	return appTestClient{SocketPath: path}, requestReceived, func() {
		close(release)
		_ = listener.Close()
		defer func() { _ = os.RemoveAll(dir) }()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("stalling app daemon returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("stalling app daemon did not stop")
		}
	}
}

func waitForAppDaemonRequest(t *testing.T, requestReceived <-chan struct{}) {
	t.Helper()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("daemon status request did not reach stalling daemon")
	}
}
