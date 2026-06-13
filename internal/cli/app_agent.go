package cli

import (
	"errors"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

type versionOutput struct {
	SchemaVersion string `json:"schema_version"`
	CLI           string `json:"cli"`
	Version       string `json:"version"`
	Revision      string `json:"revision,omitempty"`
	Display       string `json:"display"`
}

type agentContextOutput struct {
	SchemaVersion string                    `json:"schema_version"`
	CLI           string                    `json:"cli"`
	Version       string                    `json:"version"`
	Commands      map[string]commandContext `json:"commands"`
	Config        configContext             `json:"config"`
	Available     availableContext          `json:"available"`
	Conventions   conventionsContext        `json:"conventions"`
}

type commandContext struct {
	Summary     string                    `json:"summary"`
	Subcommands map[string]commandContext `json:"subcommands,omitempty"`
	Flags       []flagContext             `json:"flags,omitempty"`
	Outputs     []string                  `json:"outputs,omitempty"`
	Notes       []string                  `json:"notes,omitempty"`
}

type flagContext struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Repeatable  bool     `json:"repeatable,omitempty"`
	Default     string   `json:"default,omitempty"`
	Values      []string `json:"values,omitempty"`
	Description string   `json:"description"`
}

type configContext struct {
	Discovery      []string `json:"discovery"`
	InspectCommand string   `json:"inspect_command"`
}

type availableContext struct {
	ProfileConfig *profileConfigContext `json:"profile_config,omitempty"`
}

type profileConfigContext struct {
	SourcePath     string   `json:"source_path"`
	DefaultProfile string   `json:"default_profile,omitempty"`
	Profiles       []string `json:"profiles"`
	Error          string   `json:"error,omitempty"`
}

type conventionsContext struct {
	JSONFlag         string   `json:"json_flag"`
	NoPromptFlag     string   `json:"no_prompt_flag"`
	DryRunFlag       string   `json:"dry_run_flag"`
	SecretSafety     []string `json:"secret_safety"`
	MutationBoundary []string `json:"mutation_boundary"`
}

func (a App) runVersion(command Command) int {
	if !command.OutputJSON {
		a.stdoutln(command.VersionText)
		return 0
	}
	if err := a.writeJSON(versionOutput{
		SchemaVersion: "1",
		CLI:           "agent-secret",
		Version:       buildinfo.Version,
		Revision:      buildinfo.Revision,
		Display:       buildinfo.DisplayVersion(),
	}); err != nil {
		a.stderrf("agent-secret: write version json: %v\n", err)
		return 1
	}
	return 0
}

func (a App) runAgentContext(command Command) int {
	output := agentContextOutput{
		SchemaVersion: "1",
		CLI:           "agent-secret",
		Version:       buildinfo.DisplayVersion(),
		Commands:      agentContextCommands(),
		Config: configContext{
			Discovery:      []string{"agent-secret.yml", ".agent-secret.yml"},
			InspectCommand: "agent-secret profile list --json",
		},
		Available: availableContext{
			ProfileConfig: profileConfigContextFor(command.AgentContextOptions.ConfigPath),
		},
		Conventions: conventionsContext{
			JSONFlag:     "--json",
			NoPromptFlag: "--reuse-only",
			DryRunFlag:   "--dry-run",
			SecretSafety: []string{
				"secret values are never printed by agent-secret",
				"exec passes child stdin/stdout/stderr through unchanged",
				"item describe returns metadata only",
				"session create returns a public session id and secret session token; with-session never prints values",
			},
			MutationBoundary: []string{
				"exec --dry-run validates without prompting or spawning",
				"exec --reuse-only fails instead of opening a new approval prompt",
				"agent-secret repair safely refreshes trusted background helper mismatches",
				"session destroy or helper stop clears background-helper session values",
			},
		},
	}
	if err := a.writeJSON(output); err != nil {
		a.stderrf("agent-secret: write agent-context json: %v\n", err)
		return 1
	}
	return 0
}

func profileConfigContextFor(configPath string) *profileConfigContext {
	info, err := profileconfig.Inspect(profileconfig.LoadOptions{ConfigPath: configPath})
	if err != nil {
		if errors.Is(err, profileconfig.ErrConfigNotFound) {
			return nil
		}
		return &profileConfigContext{Error: err.Error()}
	}
	profiles := make([]string, 0, len(info.Profiles))
	for _, profile := range info.Profiles {
		profiles = append(profiles, profile.Name)
	}
	return &profileConfigContext{
		SourcePath:     info.SourcePath,
		DefaultProfile: info.DefaultProfile,
		Profiles:       profiles,
	}
}

func agentContextCommands() map[string]commandContext {
	return map[string]commandContext{
		"agent-context": {
			Summary: "Print a versioned machine-readable description of the CLI surface.",
			Flags: []flagContext{
				{Name: "--config", Type: "path", Description: "Profile config path for available profile discovery."},
				{Name: "--json", Type: "bool", Default: "true", Description: "Accepted for consistency; output is always JSON."},
			},
			Outputs: []string{"json"},
		},
		"daemon": {
			Summary: "Run low-level diagnostics for the per-user daemon.",
			Subcommands: map[string]commandContext{
				"status": {Summary: "Report whether the daemon is running.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
				"start":  {Summary: "Start the daemon and report its status.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
				"stop":   {Summary: "Stop the daemon and clear helper-owned reusable approvals.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
			},
		},
		"doctor": {
			Summary: "Print non-secret local setup diagnostics, including background helper health.",
			Flags:   jsonFlag(),
			Outputs: []string{"text", "json"},
		},
		"repair": {
			Summary: "Inspect and repair Agent Secret background helper state.",
			Flags:   jsonFlag(),
			Outputs: []string{"text", "json"},
		},
		"exec": {
			Summary: "Run a command with approved secrets injected as environment variables.",
			Flags: []flagContext{
				{Name: "--reason", Type: "string", Description: "Human-readable reason shown to the approver."},
				{Name: "--secret", Type: "mapping", Repeatable: true, Description: "Secret alias mapping: ALIAS=op://vault/item/field or ALIAS=bws://source/secret-uuid."},
				{Name: "--profile", Type: "string", Description: "Load a named project profile."},
				{Name: "--only", Type: "string", Repeatable: true, Description: "Filter profile/env-file aliases; comma-separated values are accepted."},
				{Name: "--env-file", Type: "path", Repeatable: true, Description: "Load dotenv entries; op:// and bws:// values become approved refs."},
				{Name: "--account", Type: "string", Description: "Default 1Password account for refs without a config account."},
				{Name: "--config", Type: "path", Description: "Profile config path."},
				{Name: "--cwd", Type: "path", Description: "Child working directory."},
				{Name: "--ttl", Type: "duration", Default: request.DefaultExecTTL.String(), Description: "Approval TTL.", Values: []string{request.MinRequestTTL.String() + ".." + request.MaxRequestTTL.String()}},
				{Name: "--override-env", Type: "bool", Description: "Allow approved aliases to replace existing child env vars."},
				{Name: "--force-refresh", Type: "bool", Description: "Refetch values for a matching reusable approval before delivery."},
				{Name: "--dry-run", Type: "bool", Description: "Validate request and print preflight output without prompting or spawning."},
				{Name: "--reuse-only", Type: "bool", Description: "Use an existing reusable approval or fail without prompting."},
				{Name: "--allow-mutable-executable", Type: "bool", Description: "Allow a user-owned or writable executable path after surfacing the approval warning."},
				{Name: "--json", Type: "bool", Description: "Only valid with --dry-run."},
			},
			Outputs: []string{"child passthrough", "dry-run text", "dry-run json"},
			Notes:   []string{"the wrapped command must appear after -- as argv", "normal exec has no JSON mode because child output is passed through unchanged"},
		},
		"install-cli": {
			Summary: "Install or repair the command symlink for this user.",
			Flags: append([]flagContext{
				{Name: "--bin-dir", Type: "path", Default: "~/.local/bin", Description: "Directory that should contain the agent-secret command."},
				{Name: "--force", Type: "bool", Description: "Replace an existing regular file or different symlink."},
			}, jsonFlag()...),
			Outputs: []string{"text", "json"},
		},
		"session": {
			Summary: "Create, list, and destroy bounded background-helper secret sessions.",
			Subcommands: map[string]commandContext{
				"create": {
					Summary: "Ask for approval, resolve refs, and return a session id plus token.",
					Flags: []flagContext{
						{Name: "--reason", Type: "string", Description: "Human-readable reason shown to the approver."},
						{Name: "--secret", Type: "mapping", Repeatable: true, Description: "Secret alias mapping: ALIAS=op://vault/item/field or ALIAS=bws://source/secret-uuid."},
						{Name: "--profile", Type: "string", Description: "Load a named project profile."},
						{Name: "--only", Type: "string", Repeatable: true, Description: "Filter profile/env-file aliases; comma-separated values are accepted."},
						{Name: "--env-file", Type: "path", Repeatable: true, Description: "Load dotenv entries; op:// and bws:// values become approved refs."},
						{Name: "--account", Type: "string", Description: "Default 1Password account for refs without a config account."},
						{Name: "--config", Type: "path", Description: "Profile config path."},
						{Name: "--cwd", Type: "path", Description: "Session working directory."},
						{Name: "--ttl", Type: "duration", Default: request.DefaultSessionTTL.String(), Description: "Session TTL.", Values: []string{request.MinRequestTTL.String() + ".." + request.MaxRequestTTL.String()}},
						{Name: "--max-reads", Type: "int", Default: "1", Values: []string{"1..20"}, Description: "Maximum with-session resolves before the session is exhausted."},
						{Name: "--override-env", Type: "bool", Description: "Allow with-session to replace existing child env vars with approved aliases."},
						{Name: "--json", Type: "bool", Description: "Print session metadata as JSON."},
					},
					Outputs: []string{"text", "json"},
					Notes:   []string{"returns a public session id for management and a secret session token for with-session", "secret values stay in Agent Secret's background helper memory until TTL, max reads, destroy, or helper stop"},
				},
				"list": {
					Summary: "List active session ids and non-secret metadata.",
					Flags:   jsonFlag(),
					Outputs: []string{"text", "json"},
				},
				"destroy": {
					Summary: "Destroy one session and clear its cached values.",
					Flags: append([]flagContext{
						{Name: "--all", Type: "bool", Description: "Destroy all active sessions."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
			},
		},
		"with-session": {
			Summary: "Run one command with secrets from an approved session.",
			Flags: []flagContext{
				{Name: "--cwd", Type: "path", Description: "Child working directory; must match the session cwd."},
				{Name: "--allow-mutable-executable", Type: "bool", Description: "Allow a user-owned or writable executable path after surfacing the approval warning."},
			},
			Outputs: []string{"child passthrough"},
			Notes:   []string{"usage: agent-secret with-session SESSION_TOKEN -- COMMAND [ARG...]", "session values are injected into the child environment and never printed"},
		},
		"bitwarden": {
			Summary: "Manage local Bitwarden Secrets Manager token aliases.",
			Subcommands: map[string]commandContext{
				"secrets-manager token install": {
					Summary: "Store a Bitwarden Secrets Manager access token in the macOS Keychain under a local alias.",
					Flags: append([]flagContext{
						{Name: "--alias", Type: "string", Description: "Local token alias."},
						{Name: "--from-stdin", Type: "bool", Description: "Read the access token from stdin instead of prompting with hidden terminal input."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
					Notes:   []string{"the token value is never printed", "without --from-stdin, install requires an interactive terminal"},
				},
				"secrets-manager token status": {
					Summary: "Report whether a local Bitwarden token alias is installed.",
					Flags: append([]flagContext{
						{Name: "--alias", Type: "string", Description: "Local token alias."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
				"secrets-manager token remove": {
					Summary: "Remove a local Bitwarden token alias from the macOS Keychain.",
					Flags: append([]flagContext{
						{Name: "--alias", Type: "string", Description: "Local token alias."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
			},
		},
		"item": {
			Summary: "Inspect 1Password item metadata without revealing secret values.",
			Subcommands: map[string]commandContext{
				"describe": {
					Summary: "Show approved item metadata.",
					Flags: []flagContext{
						{Name: "--account", Type: "string", Description: "1Password account override."},
						{Name: "--config", Type: "path", Description: "Profile config path."},
						{Name: "--format", Type: "enum", Default: "text", Values: []string{"text", "json", "env-refs"}, Description: "Output format."},
						{Name: "--prefix", Type: "string", Description: "Prefix generated aliases in env-refs output."},
						{Name: "--reason", Type: "string", Default: "Inspect 1Password item metadata", Description: "Human-readable reason shown to the approver."},
						{Name: "--ttl", Type: "duration", Default: request.DefaultItemDescribeTTL.String(), Values: []string{request.MinRequestTTL.String() + ".." + request.MaxRequestTTL.String()}, Description: "Approval TTL."},
					},
					Outputs: []string{"text", "json", "env-refs"},
				},
			},
		},
		"profile": {
			Summary: "Inspect project profile configuration without resolving secret values.",
			Subcommands: map[string]commandContext{
				"list": {
					Summary: "List profile names from the discovered config.",
					Flags: append([]flagContext{
						{Name: "--config", Type: "path", Description: "Profile config path."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
				"show": {
					Summary: "Show one resolved profile, defaulting to default_profile.",
					Flags: append([]flagContext{
						{Name: "--config", Type: "path", Description: "Profile config path."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
			},
		},
		"skill-install": {
			Summary: "Install or repair the bundled Agent Secret coding-agent skill.",
			Flags: append([]flagContext{
				{Name: "--skills-dir", Type: "path", Default: "~/.agents/skills", Description: "Directory that should contain the agent-secret skill."},
				{Name: "--force", Type: "bool", Description: "Replace an existing regular file or different symlink."},
			}, jsonFlag()...),
			Outputs: []string{"text", "json"},
		},
		"version": {
			Summary: "Print the installed agent-secret version.",
			Flags:   jsonFlag(),
			Outputs: []string{"text", "json"},
		},
	}
}

func jsonFlag() []flagContext {
	return []flagContext{{Name: "--json", Type: "bool", Description: "Print JSON output."}}
}
