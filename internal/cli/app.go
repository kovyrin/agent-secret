package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"

	"github.com/kovyrin/agent-secret/internal/bwsm"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/randid"
	"github.com/kovyrin/agent-secret/internal/request"
)

type App struct {
	Parser              Parser
	InstallCLI          func(install.CLIOptions) (install.CLIResult, error)
	InstallSkill        func(install.SkillOptions) (install.SkillResult, error)
	BitwardenTokens     bwsm.Store
	SecretPrompt        func(prompt string) (string, error)
	RandomReader        io.Reader
	DoctorApproverCheck func(context.Context) error
	Stdin               io.Reader
	Stdout              io.Writer
	Stderr              io.Writer
	managerFactory      daemonManagerFactory
}

type ControlManagerFactory func() (control.Manager, error)

type daemonManagerFactory func() (daemonManager, error)

type daemonManager interface {
	EnsureRunning(ctx context.Context) error
	Repair(ctx context.Context) (control.RepairResult, error)
	Connect(ctx context.Context) (daemonClient, error)
	Status(ctx context.Context) (protocol.StatusPayload, error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	CheckOnePassword(ctx context.Context, account string) error
	SocketPath() string
}

type daemonClient interface {
	Close() error
	RequestExec(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.ExecRequest,
	) (protocol.ExecResponsePayload, error)
	RequestGCPExec(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.GCPExecRequest,
	) (protocol.GCPCommandResponsePayload, error)
	CreateGCPSession(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.GCPSessionCreateRequest,
		handle string,
	) (protocol.GCPSessionCreateResponsePayload, error)
	ListGCPSessions(ctx context.Context, cwd string) (protocol.GCPSessionListResponsePayload, error)
	DestroyGCPSession(ctx context.Context, req request.GCPSessionDestroyRequest) (protocol.GCPSessionDestroyResponsePayload, error)
	UseGCPSession(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.GCPSessionUseRequest,
	) (protocol.GCPCommandResponsePayload, error)
	DescribeItem(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.ItemDescribeRequest,
	) (protocol.ItemDescribeResponsePayload, error)
	CreateSession(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.SessionCreateRequest,
	) (protocol.SessionCreateResponsePayload, error)
	ResolveSession(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.SessionResolveRequest,
	) (protocol.SessionResolveResponsePayload, error)
	DestroySession(ctx context.Context, req request.SessionDestroyRequest) (protocol.SessionDestroyResponsePayload, error)
	ListSessions(ctx context.Context) (protocol.SessionListResponsePayload, error)
	ReportStarted(ctx context.Context, correlation protocol.Correlation, childPID int) error
	ReportCompleted(ctx context.Context, correlation protocol.Correlation, exitCode int, signal string) error
}

type daemonControlManager struct {
	control.Manager
}

func (m daemonControlManager) Connect(ctx context.Context) (daemonClient, error) {
	return m.Manager.Connect(ctx)
}

func NewApp(newManager ControlManagerFactory, stdout io.Writer, stderr io.Writer) App {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if newManager == nil {
		newManager = func() (control.Manager, error) {
			return control.NewManager("")
		}
	}
	return App{
		Parser:          NewParser(),
		InstallCLI:      install.InstallCLI,
		InstallSkill:    install.InstallSkill,
		BitwardenTokens: bwsm.NewKeychainStore(""),
		RandomReader:    rand.Reader,
		Stdin:           os.Stdin,
		Stdout:          stdout,
		Stderr:          stderr,
		managerFactory:  newDaemonManagerFactory(newManager),
	}
}

func newDaemonManagerFactory(newManager ControlManagerFactory) daemonManagerFactory {
	return func() (daemonManager, error) {
		manager, err := newManager()
		if err != nil {
			return nil, err
		}
		return daemonControlManager{Manager: manager}, nil
	}
}

func (a App) daemonManager() (daemonManager, error) {
	factory := a.managerFactory
	if factory == nil {
		factory = newDaemonManagerFactory(func() (control.Manager, error) {
			return control.NewManager("")
		})
	}
	return factory()
}

func (a App) Run(ctx context.Context, args []string) int {
	command, err := a.Parser.Parse(args)
	if errors.Is(err, ErrHelpRequested) {
		a.stdoutln(command.HelpText)
		return 0
	}
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 2
	}

	switch command.Kind {
	case KindHelp:
		a.stdoutln(command.HelpText)
		return 0
	case KindVersion:
		return a.runVersion(command)
	case KindAgentContext:
		return a.runAgentContext(command)
	case KindExec:
		return a.runExec(ctx, command)
	case KindSessionCreate:
		return a.runSessionCreate(ctx, command)
	case KindSessionList:
		return a.runSessionList(ctx, command)
	case KindSessionDestroy:
		return a.runSessionDestroy(ctx, command)
	case KindWithSession:
		return a.runWithSession(ctx, command)
	case KindGCPExec:
		return a.runGCPExec(ctx, command)
	case KindGCPSessionCreate:
		return a.runGCPSessionCreate(ctx, command)
	case KindGCPSessionList:
		return a.runGCPSessionList(ctx, command)
	case KindGCPSessionDestroy:
		return a.runGCPSessionDestroy(ctx, command)
	case KindGCPWithSession:
		return a.runGCPWithSession(ctx, command)
	case KindGCPAuthStatus, KindGCPAuthLogin, KindGCPAuthLogout:
		return a.runGCPAuth(ctx, command)
	case KindItemDescribe:
		return a.runItemDescribe(ctx, command)
	case KindProfileList:
		return a.runProfileList(command)
	case KindProfileShow:
		return a.runProfileShow(command)
	case KindBitwarden:
		return a.runBitwarden(ctx, command)
	case KindDaemonStatus:
		return a.runDaemonStatusWithOutput(ctx, command.OutputJSON)
	case KindDaemonStart:
		return a.runDaemonStart(ctx, command)
	case KindDaemonStop:
		return a.runDaemonStop(ctx, command)
	case KindDoctor:
		return a.runDoctor(ctx, command)
	case KindRepair:
		return a.runRepair(ctx, command)
	case KindInstallCLI:
		return a.runInstallCLI(ctx, command)
	case KindSkillInstall:
		return a.runSkillInstall(command)
	default:
		a.stderrf("agent-secret: unsupported command %s\n", command.Kind)
		return 2
	}
}

func (a App) randomID(prefix string) (string, error) {
	return randid.Generate(a.RandomReader, prefix)
}
