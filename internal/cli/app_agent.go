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
			},
			MutationBoundary: []string{
				"exec --dry-run validates without prompting or spawning",
				"exec --reuse-only fails instead of opening a new approval prompt",
				"daemon stop clears daemon-owned reusable approvals and cached values",
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
			Summary: "Troubleshoot the hidden per-user daemon.",
			Subcommands: map[string]commandContext{
				"status": {Summary: "Report whether the daemon is running.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
				"start":  {Summary: "Start the daemon and report its status.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
				"stop":   {Summary: "Stop the daemon and clear daemon-owned reusable approvals.", Flags: jsonFlag(), Outputs: []string{"text", "json"}},
			},
		},
		"doctor": {
			Summary: "Print non-secret local setup diagnostics.",
			Flags:   jsonFlag(),
			Outputs: []string{"text", "json"},
		},
		"exec": {
			Summary: "Run a command with approved secrets injected as environment variables.",
			Flags: []flagContext{
				{Name: "--reason", Type: "string", Description: "Human-readable reason shown to the approver."},
				{Name: "--secret", Type: "mapping", Repeatable: true, Description: "Secret alias mapping: ALIAS=op://vault/item/field."},
				{Name: "--profile", Type: "string", Description: "Load a named project profile."},
				{Name: "--only", Type: "string", Repeatable: true, Description: "Filter profile/env-file aliases; comma-separated values are accepted."},
				{Name: "--env-file", Type: "path", Repeatable: true, Description: "Load dotenv entries; op:// values become approved refs."},
				{Name: "--account", Type: "string", Description: "Default 1Password account for refs without a config account."},
				{Name: "--config", Type: "path", Description: "Profile config path."},
				{Name: "--cwd", Type: "path", Description: "Child working directory."},
				{Name: "--ttl", Type: "duration", Default: request.DefaultExecTTL.String(), Description: "Approval TTL.", Values: []string{request.MinRequestTTL.String() + ".." + request.MaxRequestTTL.String()}},
				{Name: "--override-env", Type: "bool", Description: "Allow approved aliases to replace existing child env vars."},
				{Name: "--force-refresh", Type: "bool", Description: "Refetch values for a matching reusable approval before delivery."},
				{Name: "--dry-run", Type: "bool", Description: "Validate request and print preflight output without prompting or spawning."},
				{Name: "--reuse-only", Type: "bool", Description: "Use an existing reusable approval or fail without prompting."},
				{Name: "--json", Type: "bool", Description: "Only valid with --dry-run."},
			},
			Outputs: []string{"child passthrough", "dry-run text", "dry-run json"},
			Notes:   []string{"the wrapped command must appear after -- as argv", "normal exec has no JSON mode because child output is passed through unchanged"},
		},
		"gcp": {
			Summary: "Run commands with approved short-lived GCP access tokens and isolated Cloud SDK state.",
			Subcommands: map[string]commandContext{
				"exec": {
					Summary: "Run one command with approved GCP access.",
					Flags: []flagContext{
						{Name: "--profile", Type: "string", Description: "Load a GCP profile from project config."},
						{Name: "--google-account", Type: "string", Description: "Google bootstrap identity alias."},
						{Name: "--project", Type: "string", Description: "Intended GCP project."},
						{Name: "--service-account", Type: "string", Description: "Service account to impersonate."},
						{Name: "--scope", Type: "string", Repeatable: true, Description: "OAuth scope."},
						{Name: "--reason", Type: "string", Description: "Human-readable reason shown to the approver."},
						{Name: "--ttl", Type: "duration", Default: request.DefaultExecTTL.String(), Values: []string{request.MinRequestTTL.String() + ".." + request.MaxRequestTTL.String()}, Description: "Approval TTL."},
						{Name: "--dry-run", Type: "bool", Description: "Validate without prompting, minting, or spawning."},
						{Name: "--reuse-only", Type: "bool", Description: "Use an existing reusable approval or fail without prompting."},
						{Name: "--json", Type: "bool", Description: "Only valid with --dry-run."},
					},
					Outputs: []string{"child passthrough", "dry-run text", "dry-run json"},
				},
				"session create": {
					Summary: "Approve a config-backed multi-command GCP session.",
					Flags: []flagContext{
						{Name: "--profile", Type: "string", Description: "Load a GCP profile from project config."},
						{Name: "--reason", Type: "string", Description: "Human-readable workflow reason."},
						{Name: "--ttl", Type: "duration", Default: request.DefaultGCPSessionTTL.String(), Values: []string{request.MinRequestTTL.String() + ".." + request.MaxGCPSessionTTL.String()}, Description: "Session TTL."},
						{Name: "--max-command-starts", Type: "int", Default: "20", Description: "Maximum approved with-session command starts."},
						{Name: "--json", Type: "bool", Description: "Print JSON output."},
					},
					Outputs: []string{"text", "json"},
				},
				"with-session": {
					Summary: "Run one command inside an approved GCP session.",
					Outputs: []string{"child passthrough"},
				},
				"auth status": {
					Summary: "Show app-owned Google bootstrap auth stored in Keychain.",
					Flags: append([]flagContext{
						{Name: "--google-account", Type: "string", Description: "Optional Google bootstrap identity alias filter."},
					}, jsonFlag()...),
					Outputs: []string{"text", "json"},
				},
				"auth login": {
					Summary: "Start daemon-owned Google OAuth login with the bundled OAuth client and store bootstrap state in Keychain.",
					Flags: []flagContext{
						{Name: "--google-account", Type: "string", Description: "Google bootstrap identity alias."},
						{Name: "--expected-email", Type: "string", Description: "Refuse login unless Google reports this email."},
						{Name: "--json", Type: "bool", Description: "Print JSON output."},
					},
					Outputs: []string{"text", "json"},
				},
				"auth logout": {
					Summary: "Remove app-owned Google bootstrap auth from Keychain.",
					Flags: []flagContext{
						{Name: "--google-account", Type: "string", Description: "Google bootstrap identity alias."},
						{Name: "--json", Type: "bool", Description: "Print JSON output."},
					},
					Outputs: []string{"text", "json"},
				},
			},
		},
		"install-cli": {
			Summary: "Install or repair the command symlink for this user.",
			Flags: append([]flagContext{
				{Name: "--bin-dir", Type: "path", Default: "~/.local/bin", Description: "Directory that should contain the agent-secret command."},
				{Name: "--force", Type: "bool", Description: "Replace an existing regular file or different symlink."},
			}, jsonFlag()...),
			Outputs: []string{"text", "json"},
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
