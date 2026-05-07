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
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
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
		"--reason", "Run helper",
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
		"--reason", "Run helper",
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
		"--reason", "Run helper",
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
		"--reason", "Run helper",
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
		"--reason", "Run helper",
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
		"--reason", "Run helper",
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
		!strings.Contains(stdout.String(), "daemon startup: ok") ||
		!strings.Contains(stdout.String(), "socket directory: private") ||
		!strings.Contains(stdout.String(), "native approver: ok") ||
		!strings.Contains(stdout.String(), "1password desktop integration: ok") {
		t.Fatalf("doctor output missing diagnostics: %q", stdout.String())
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
}

func TestAppDaemonStatusReportsStoppedAfterRequestCancellation(t *testing.T) {
	client, requestReceived, cleanup := startStallingAppDaemon(t)
	defer cleanup()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{
		SocketPath: client.SocketPath,
		DaemonPath: os.Args[0],
	}, &stdout, &stderr)

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

func TestAppInstallCLIWarnsWhenCommandDirIsNotOnPath(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	t.Setenv("HOME", home)
	t.Setenv("PATH", filepath.Join(t.TempDir(), "other-bin"))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{}, &stdout, &stderr)
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
	wantOneLiner := "grep -qxF 'export PATH=\"$HOME/.local/bin:$PATH\"' \"$HOME/.zprofile\" 2>/dev/null || " +
		"printf '\\n%s\\n' 'export PATH=\"$HOME/.local/bin:$PATH\"' >> \"$HOME/.zprofile\"; exec zsh -l"
	if !strings.Contains(stdout.String(), wantOneLiner) {
		t.Fatalf("install-cli stdout = %q, want zsh setup one-liner %q", stdout.String(), wantOneLiner)
	}
}

func TestAppInstallCLISkipsPathWarningWhenCommandDirIsOnPath(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	t.Setenv("PATH", strings.Join([]string{filepath.Join(t.TempDir(), "other-bin"), binDir}, string(os.PathListSeparator)))

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{}, &stdout, &stderr)
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
		{"install-cli", "--bin-dir", filepath.Join(t.TempDir(), "bin"), "--force"},
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

func runInstallCommandTest(t *testing.T, args []string, configure func(*App), stdoutWant string) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{}, &stdout, &stderr)
	configure(&app)

	code := app.Run(context.Background(), args)
	if code != 0 {
		t.Fatalf("%v exit=%d stderr=%q stdout=%q", args, code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), stdoutWant) {
		t.Fatalf("%v stdout = %q, want %q", args, stdout.String(), stdoutWant)
	}
}

func TestAppReportsParseErrorsAndStoppedDaemonStatus(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}, &stdout, &stderr)

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
		"daemon startup: ok",
		"daemon: running pid=5678",
		"socket directory: private",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor output = %q, want %q", stdout.String(), want)
		}
	}
	if manager.ensureCalls != 1 || manager.statusCalls != 1 {
		t.Fatalf("manager calls: ensure=%d status=%d", manager.ensureCalls, manager.statusCalls)
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

func TestAppExecReportsDaemonStartFailureBeforeSpawn(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := newTestApp(control.Manager{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecReportsDaemonStartFailureBeforeSpawn", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "start daemon") {
		t.Fatalf("stderr = %q, want start daemon failure", stderr.String())
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
		"--reason", "Run helper",
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

type appTestClient struct {
	SocketPath string
}

type appFakeDaemonManager struct {
	socketPath string
	client     daemonClient
	clients    []daemonClient
	status     protocol.StatusPayload

	ensureErr  error
	connectErr error
	statusErr  error
	startErr   error
	stopErr    error
	checkErr   error

	ensureCalls  int
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
	execPayload         protocol.ExecResponsePayload
	itemDescribePayload protocol.ItemDescribeResponsePayload

	requestErr         error
	itemDescribeErr    error
	reportStartedErr   error
	reportCompletedErr error
	closeErr           error

	requestExecCalls     int
	itemDescribeCalls    int
	requests             []request.ExecRequest
	itemDescribeRequests []request.ItemDescribeRequest
	closeCalls           int
	startedPIDs          []int
	completedExitCodes   []int
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

func (c *appFakeDaemonClient) DescribeItem(
	_ context.Context,
	_ protocol.Correlation,
	req request.ItemDescribeRequest,
) (protocol.ItemDescribeResponsePayload, error) {
	c.itemDescribeCalls++
	c.itemDescribeRequests = append(c.itemDescribeRequests, req)
	return c.itemDescribePayload, c.itemDescribeErr
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
	return control.Manager{SocketPath: client.SocketPath, DaemonPath: os.Args[0]}
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

func (r *appResolver) Resolve(_ context.Context, ref string, _ string) (string, error) {
	return r.values[ref], nil
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

type appAllowPeer struct{}

func (appAllowPeer) Info(conn *net.UnixConn) (peercred.Info, error) {
	return peercred.Inspect(conn)
}

func (appAllowPeer) Validate(_ *net.UnixConn) error {
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
		case protocol.TypeItemDescribe, protocol.TypeCommandStarted, protocol.TypeCommandCompleted:
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
