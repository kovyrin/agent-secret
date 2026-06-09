package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/opaccount"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
)

type daemonStatusOutput struct {
	SchemaVersion string `json:"schema_version"`
	Running       bool   `json:"running"`
	PID           int    `json:"pid,omitempty"`
	Error         string `json:"error,omitempty"`
}

type daemonStopOutput struct {
	SchemaVersion string `json:"schema_version"`
	Stopped       bool   `json:"stopped"`
	Error         string `json:"error,omitempty"`
}

type repairOutput struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	PID           int    `json:"pid,omitempty"`
	Error         string `json:"error,omitempty"`
}

type doctorOutput struct {
	SchemaVersion string        `json:"schema_version"`
	OK            bool          `json:"ok"`
	Platform      string        `json:"platform"`
	DaemonSocket  string        `json:"daemon_socket"`
	Checks        []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Path    string `json:"path,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Account string `json:"account,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (a App) runDaemonStatusWithOutput(ctx context.Context, jsonOutput bool) int {
	manager, err := a.daemonManager()
	if err != nil {
		if jsonOutput {
			return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: false, Error: err.Error()}, 1)
		}
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	status, err := manager.Status(ctx)
	if err != nil {
		if jsonOutput {
			return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: false, Error: err.Error()}, 1)
		}
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	if jsonOutput {
		return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: true, PID: status.PID}, 0)
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStart(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		if command.OutputJSON {
			return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: false, Error: err.Error()}, 1)
		}
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.Start(ctx); err != nil {
		if command.OutputJSON {
			return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: false, Error: err.Error()}, 1)
		}
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	status, err := manager.Status(ctx)
	if err != nil {
		if command.OutputJSON {
			return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: false, Error: err.Error()}, 1)
		}
		a.stderrf("agent-secret: daemon started but status failed: %v\n", err)
		return 1
	}
	if command.OutputJSON {
		return a.writeDaemonStatusJSON(daemonStatusOutput{SchemaVersion: "1", Running: true, PID: status.PID}, 0)
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStop(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		if command.OutputJSON {
			return a.writeDaemonStopJSON(daemonStopOutput{SchemaVersion: "1", Stopped: false, Error: err.Error()}, 1)
		}
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.Stop(ctx); err != nil {
		if command.OutputJSON {
			return a.writeDaemonStopJSON(daemonStopOutput{SchemaVersion: "1", Stopped: false, Error: err.Error()}, 1)
		}
		a.stderrf("agent-secret: stop daemon: %v\n", err)
		return 1
	}
	if command.OutputJSON {
		return a.writeDaemonStopJSON(daemonStopOutput{SchemaVersion: "1", Stopped: true}, 0)
	}
	a.stdoutln("agent-secretd: stopped")
	return 0
}

func (a App) runRepair(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		if command.OutputJSON {
			return a.writeRepairJSON(repairOutput{
				SchemaVersion: "1",
				Status:        string(control.RepairStatusRepairRequired),
				Error:         err.Error(),
			}, 1)
		}
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	result, err := manager.Repair(ctx)
	if err != nil {
		if command.OutputJSON {
			return a.writeRepairJSON(repairOutput{
				SchemaVersion: "1",
				Status:        string(control.RepairStatusRepairRequired),
				Error:         err.Error(),
			}, 1)
		}
		a.stdoutln("Background helper: repair required")
		a.stdoutln("Run `agent-secret repair` after closing any unexpected Agent Secret helper processes.")
		return 1
	}
	if command.OutputJSON {
		return a.writeRepairJSON(repairOutput{
			SchemaVersion: "1",
			Status:        string(result.Status),
			PID:           result.PID,
		}, 0)
	}
	switch result.Status {
	case control.RepairStatusRefreshed:
		a.stdoutln("Background helper: refreshed")
	case control.RepairStatusOK:
		a.stdoutln("Background helper: ok")
	case control.RepairStatusRepairRequired:
		a.stdoutln("Background helper: repair required")
	default:
		a.stdoutf("Background helper: %s\n", result.Status)
	}
	return 0
}

func (a App) runDoctor(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		if command.OutputJSON {
			return a.writeJSONError("initialize background helper manager", err)
		}
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	healthy := true
	checks := make([]doctorCheck, 0, 8)
	platform := runtime.GOOS + "/" + runtime.GOARCH
	jsonOutput := command.OutputJSON
	if !jsonOutput {
		a.stdoutln("agent-secret doctor")
		a.stdoutf("platform: %s\n", platform)
		a.stdoutf("background helper socket: %s\n", manager.SocketPath())
	}

	var check doctorCheck
	var checkOK bool
	check, checkOK = a.auditLogDoctorCheck(ctx, jsonOutput)
	checks, healthy = appendDoctorCheck(checks, healthy, check, checkOK)
	check, checkOK = a.backgroundHelperDoctorCheck(ctx, manager, jsonOutput)
	checks, healthy = appendDoctorCheck(checks, healthy, check, checkOK)
	check, checkOK = a.socketDirectoryDoctorCheck(manager, jsonOutput)
	checks, healthy = appendDoctorCheck(checks, healthy, check, checkOK)
	if check := a.DoctorApproverCheck; check != nil {
		check, checkOK := a.nativeApproverDoctorCheck(ctx, check, jsonOutput)
		checks, healthy = appendDoctorCheck(checks, healthy, check, checkOK)
	}

	account, configSource, err := doctorOnePasswordAccount()
	if err != nil {
		healthy = false
		checks = append(checks, doctorCheck{Name: "project_config", Status: "failed", Error: err.Error()})
		if !jsonOutput {
			a.stdoutf("project config: failed (%v)\n", err)
		}
	}
	if configSource != "" {
		checks = append(checks, doctorCheck{Name: "project_config", Status: "ok", Path: configSource})
		if !jsonOutput {
			a.stdoutf("project config: %s\n", configSource)
		}
	}
	displayAccount := displayOnePasswordAccount(account)
	if !jsonOutput {
		a.stdoutf("1password account: %s\n", displayAccount)
	}
	check, checkOK = a.onePasswordDoctorCheck(ctx, manager, account, displayAccount, jsonOutput)
	checks, healthy = appendDoctorCheck(checks, healthy, check, checkOK)
	if jsonOutput {
		if err := a.writeJSON(doctorOutput{
			SchemaVersion: "1",
			OK:            healthy,
			Platform:      platform,
			DaemonSocket:  manager.SocketPath(),
			Checks:        checks,
		}); err != nil {
			a.stderrf("agent-secret: write doctor json: %v\n", err)
			return 1
		}
	}
	if !healthy {
		return 1
	}
	return 0
}

func appendDoctorCheck(checks []doctorCheck, healthy bool, check doctorCheck, checkOK bool) ([]doctorCheck, bool) {
	if !checkOK {
		healthy = false
	}
	return append(checks, check), healthy
}

func (a App) auditLogDoctorCheck(ctx context.Context, jsonOutput bool) (doctorCheck, bool) {
	auditPath, err := checkAuditLogWritable(ctx)
	if err != nil {
		status := fmt.Sprintf("failed (%v)", err)
		if auditPath != "" {
			status = fmt.Sprintf("failed %s (%v)", auditPath, err)
		}
		if !jsonOutput {
			a.stdoutf("audit log: %s\n", status)
		}
		return doctorCheck{Name: "audit_log", Status: "failed", Path: auditPath, Error: err.Error()}, false
	}
	if !jsonOutput {
		a.stdoutf("audit log: writable %s\n", auditPath)
	}
	return doctorCheck{Name: "audit_log", Status: "ok", Path: auditPath}, true
}

func (a App) backgroundHelperDoctorCheck(ctx context.Context, manager daemonManager, jsonOutput bool) (doctorCheck, bool) {
	result, err := manager.Repair(ctx)
	if err != nil {
		if !jsonOutput {
			a.stdoutf("Background helper: repair required (%v)\n", err)
			a.stdoutln("Run `agent-secret repair` to inspect and repair the local helper state.")
		}
		return doctorCheck{Name: "background_helper", Status: string(control.RepairStatusRepairRequired), Error: err.Error()}, false
	}
	if !jsonOutput {
		switch result.Status {
		case control.RepairStatusRefreshed:
			a.stdoutf("Background helper: refreshed pid=%d\n", result.PID)
		case control.RepairStatusOK:
			a.stdoutf("Background helper: ok pid=%d\n", result.PID)
		case control.RepairStatusRepairRequired:
			a.stdoutln("Background helper: repair required")
		default:
			a.stdoutf("Background helper: %s pid=%d\n", result.Status, result.PID)
		}
	}
	return doctorCheck{Name: "background_helper", Status: string(result.Status), PID: result.PID}, true
}

func (a App) socketDirectoryDoctorCheck(manager daemonManager, jsonOutput bool) (doctorCheck, bool) {
	if err := socket.ValidateSocketDirectoryForPath(manager.SocketPath()); err != nil {
		if !jsonOutput {
			a.stdoutf("socket directory: failed (%v)\n", err)
		}
		return doctorCheck{Name: "socket_directory", Status: "failed", Error: err.Error()}, false
	}
	if !jsonOutput {
		a.stdoutln("socket directory: private")
	}
	return doctorCheck{Name: "socket_directory", Status: "ok"}, true
}

func (a App) nativeApproverDoctorCheck(
	ctx context.Context,
	check func(context.Context) error,
	jsonOutput bool,
) (doctorCheck, bool) {
	if err := check(ctx); err != nil {
		if !jsonOutput {
			a.stdoutf("native approver: failed (%v)\n", err)
		}
		return doctorCheck{Name: "native_approver", Status: "failed", Error: err.Error()}, false
	}
	if !jsonOutput {
		a.stdoutln("native approver: ok")
	}
	return doctorCheck{Name: "native_approver", Status: "ok"}, true
}

func (a App) onePasswordDoctorCheck(
	ctx context.Context,
	manager daemonManager,
	account string,
	displayAccount string,
	jsonOutput bool,
) (doctorCheck, bool) {
	if err := manager.CheckOnePassword(ctx, account); err != nil {
		if !jsonOutput {
			a.stdoutf("1password desktop integration: failed (%v)\n", err)
		}
		return doctorCheck{
			Name:    "1password_desktop_integration",
			Status:  "failed",
			Account: displayAccount,
			Error:   err.Error(),
		}, false
	}
	if !jsonOutput {
		a.stdoutln("1password desktop integration: ok")
	}
	return doctorCheck{Name: "1password_desktop_integration", Status: "ok", Account: displayAccount}, true
}

func (a App) writeDaemonStatusJSON(output daemonStatusOutput, code int) int {
	if err := a.writeJSON(output); err != nil {
		a.stderrf("agent-secret: write daemon status json: %v\n", err)
		return 1
	}
	return code
}

func (a App) writeDaemonStopJSON(output daemonStopOutput, code int) int {
	if err := a.writeJSON(output); err != nil {
		a.stderrf("agent-secret: write daemon stop json: %v\n", err)
		return 1
	}
	return code
}

func (a App) writeRepairJSON(output repairOutput, code int) int {
	if err := a.writeJSON(output); err != nil {
		a.stderrf("agent-secret: write repair json: %v\n", err)
		return 1
	}
	return code
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
	return opaccount.SelectConcreteDesktopAccount(
		os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT"),
		os.Getenv("OP_ACCOUNT"),
		opaccount.DetectDefaultDesktopAccount,
	)
}

func displayOnePasswordAccount(account string) string {
	if strings.TrimSpace(account) == "" {
		return "auto-detect default 1Password desktop account"
	}
	return account
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
