package cli

import (
	"errors"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrHelpRequested       = errors.New("help requested")
	ErrInvalidArguments    = errors.New("invalid arguments")
	ErrUnsupportedExecJSON = errors.New("exec supports --json only with --dry-run")
	ErrUnsupportedReuse    = errors.New("reusable approvals are chosen in the approver")
	ErrShellStringCommand  = errors.New("command must be argv after --")
)

type Kind string

const (
	KindHelp              Kind = "help"
	KindVersion           Kind = "version"
	KindAgentContext      Kind = "agent_context"
	KindExec              Kind = "exec"
	KindGCPExec           Kind = "gcp_exec"
	KindGCPSessionCreate  Kind = "gcp_session_create"
	KindGCPSessionList    Kind = "gcp_session_list"
	KindGCPSessionDestroy Kind = "gcp_session_destroy"
	KindGCPWithSession    Kind = "gcp_with_session"
	KindGCPAuthStatus     Kind = "gcp_auth_status"
	KindGCPAuthLogin      Kind = "gcp_auth_login"
	KindGCPAuthLogout     Kind = "gcp_auth_logout"
	KindItemDescribe      Kind = "item_describe"
	KindProfileList       Kind = "profile_list"
	KindProfileShow       Kind = "profile_show"
	KindDoctor            Kind = "doctor"
	KindInstallCLI        Kind = "install_cli"
	KindSkillInstall      Kind = "skill_install"
	KindDaemonStart       Kind = "daemon_start"
	KindDaemonStop        Kind = "daemon_stop"
	KindDaemonStatus      Kind = "daemon_status"
)

type Command struct {
	Kind                     Kind
	OutputJSON               bool
	ExecRequest              request.ExecRequest
	ExecEnv                  []string
	ExecDryRun               bool
	GCPExecRequest           request.GCPExecRequest
	GCPSessionCreateRequest  request.GCPSessionCreateRequest
	GCPSessionUseRequest     request.GCPSessionUseRequest
	GCPSessionDestroyRequest request.GCPSessionDestroyRequest
	GCPEnv                   []string
	GCPDryRun                bool
	ItemDescribeRequest      request.ItemDescribeRequest
	ItemDescribeFormat       itemmetadata.Format
	ItemDescribePrefix       string
	AgentContextOptions      ConfigCommandOptions
	ProfileOptions           ProfileCommandOptions
	InstallCLIOptions        install.CLIOptions
	InstallSkillOptions      install.SkillOptions
	HelpText                 string
	VersionText              string
}

type Parser struct{}

func NewParser() Parser {
	return Parser{}
}

func (p Parser) Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	}

	switch args[0] {
	case "-h", "--help", "help":
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	case "-v", "--version", "version":
		return parseVersion(args[1:])
	case "agent-context":
		return parseAgentContext(args[1:])
	case "exec":
		return p.parseExec(args[1:])
	case "gcp":
		return p.parseGCP(args[1:])
	case "item":
		return p.parseItem(args[1:], args)
	case "profile":
		return parseProfile(args[1:])
	case "daemon":
		return parseDaemon(args[1:])
	case "doctor":
		return parseDoctor(args[1:])
	case "install-cli":
		return parseInstallCLI(args[1:])
	case "skill-install":
		return parseSkillInstall(args[1:])
	default:
		return Command{}, fmt.Errorf(
			"%w: unknown command %q; expected one of: agent-context, daemon, doctor, exec, gcp, help, install-cli, item, profile, skill-install, version",
			ErrInvalidArguments,
			args[0],
		)
	}
}
