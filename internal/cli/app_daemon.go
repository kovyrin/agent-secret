package cli

import (
	"context"
	"errors"
	"os"
	"runtime"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/opaccount"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
)

func (a App) runDaemonStatus(ctx context.Context) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	status, err := manager.Status(ctx)
	if err != nil {
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStart(ctx context.Context) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.Start(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	status, err := manager.Status(ctx)
	if err != nil {
		a.stderrf("agent-secret: daemon started but status failed: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStop(ctx context.Context) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.Stop(ctx); err != nil {
		a.stderrf("agent-secret: stop daemon: %v\n", err)
		return 1
	}
	a.stdoutln("agent-secretd: stopped")
	return 0
}

func (a App) runDoctor(ctx context.Context) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	healthy := true
	a.stdoutln("agent-secret doctor")
	a.stdoutf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	a.stdoutf("daemon socket: %s\n", manager.SocketPath())
	if auditPath, err := checkAuditLogWritable(ctx); err != nil {
		healthy = false
		if auditPath == "" {
			a.stdoutf("audit log: failed (%v)\n", err)
		} else {
			a.stdoutf("audit log: failed %s (%v)\n", auditPath, err)
		}
	} else {
		a.stdoutf("audit log: writable %s\n", auditPath)
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		healthy = false
		a.stdoutf("daemon startup: failed (%v)\n", err)
	} else {
		a.stdoutln("daemon startup: ok")
	}
	if status, err := manager.Status(ctx); err == nil {
		a.stdoutf("daemon: running pid=%d\n", status.PID)
	} else {
		healthy = false
		a.stdoutf("daemon: failed (%v)\n", err)
	}
	if err := socket.ValidateSocketDirectoryForPath(manager.SocketPath()); err != nil {
		healthy = false
		a.stdoutf("socket directory: failed (%v)\n", err)
	} else {
		a.stdoutln("socket directory: private")
	}
	if check := a.DoctorApproverCheck; check != nil {
		if err := check(ctx); err != nil {
			healthy = false
			a.stdoutf("native approver: failed (%v)\n", err)
		} else {
			a.stdoutln("native approver: ok")
		}
	}
	account, configSource, err := doctorOnePasswordAccount()
	if err != nil {
		healthy = false
		a.stdoutf("project config: failed (%v)\n", err)
	}
	if configSource != "" {
		a.stdoutf("project config: %s\n", configSource)
	}
	a.stdoutf("1password account: %s\n", account)
	if err := manager.CheckOnePassword(ctx, account); err != nil {
		healthy = false
		a.stdoutf("1password desktop integration: failed (%v)\n", err)
	} else {
		a.stdoutln("1password desktop integration: ok")
	}
	if !healthy {
		return 1
	}
	return 0
}

func doctorOnePasswordAccount() (string, string, error) {
	metadata, err := profileconfig.LoadMetadata(profileconfig.LoadOptions{})
	if err == nil {
		if metadata.Account != "" {
			return metadata.Account, metadata.SourcePath, nil
		}
		return defaultOnePasswordAccount(), metadata.SourcePath, nil
	}
	if errors.Is(err, profileconfig.ErrConfigNotFound) {
		return defaultOnePasswordAccount(), "", nil
	}
	return defaultOnePasswordAccount(), "", err
}

func defaultOnePasswordAccount() string {
	return opaccount.SelectDesktopAccount(
		os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT"),
		os.Getenv("OP_ACCOUNT"),
	)
}

func checkAuditLogWritable(ctx context.Context) (string, error) {
	path, err := audit.DefaultPath()
	if err != nil {
		return "", err
	}
	writer, err := audit.OpenDefault(nil)
	if err != nil {
		return path, err
	}
	defer func() { _ = writer.Close() }()
	if err := writer.Preflight(ctx); err != nil {
		return path, err
	}
	return path, nil
}
