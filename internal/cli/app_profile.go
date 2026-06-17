package cli

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

type profileListOutput struct {
	SchemaVersion  string                     `json:"schema_version"`
	SourcePath     string                     `json:"source_path"`
	DefaultProfile string                     `json:"default_profile,omitempty"`
	Profiles       []profileListProfileOutput `json:"profiles"`
}

type profileListProfileOutput struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

type profileShowOutput struct {
	SchemaVersion string                    `json:"schema_version"`
	SourcePath    string                    `json:"source_path"`
	Profile       profileconfig.ProfileInfo `json:"profile"`
}

func (a App) runProfileList(command Command) int {
	info, err := profileconfig.Inspect(profileconfig.LoadOptions{ConfigPath: command.ProfileOptions.ConfigPath})
	if err != nil {
		return a.profileError(command.OutputJSON, "load profile config", err)
	}
	if command.OutputJSON {
		profiles := make([]profileListProfileOutput, 0, len(info.Profiles))
		for _, profile := range info.Profiles {
			profiles = append(profiles, profileListProfileOutput{Name: profile.Name, Default: profile.Default})
		}
		if err := a.writeJSON(profileListOutput{
			SchemaVersion:  "1",
			SourcePath:     info.SourcePath,
			DefaultProfile: info.DefaultProfile,
			Profiles:       profiles,
		}); err != nil {
			a.stderrf("agent-secret: write profile list json: %v\n", err)
			return 1
		}
		return 0
	}
	writer := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "config:\t%s\n", info.SourcePath); err != nil {
		return a.profileWriteError(err)
	}
	if info.DefaultProfile != "" {
		if _, err := fmt.Fprintf(writer, "default_profile:\t%s\n", info.DefaultProfile); err != nil {
			return a.profileWriteError(err)
		}
	}
	if _, err := fmt.Fprintln(writer, "profiles:"); err != nil {
		return a.profileWriteError(err)
	}
	if len(info.Profiles) == 0 {
		if _, err := fmt.Fprintln(writer, "  (none)"); err != nil {
			return a.profileWriteError(err)
		}
		return a.profileWriteError(writer.Flush())
	}
	for _, profile := range info.Profiles {
		marker := ""
		if profile.Default {
			marker = " (default)"
		}
		if _, err := fmt.Fprintf(writer, "  %s%s\n", profile.Name, marker); err != nil {
			return a.profileWriteError(err)
		}
	}
	return a.profileWriteError(writer.Flush())
}

func (a App) runProfileShow(command Command) int {
	info, err := profileconfig.Inspect(profileconfig.LoadOptions{ConfigPath: command.ProfileOptions.ConfigPath})
	if err != nil {
		return a.profileError(command.OutputJSON, "load profile config", err)
	}
	profile, err := selectProfile(info, command.ProfileOptions.Name)
	if err != nil {
		return a.profileError(command.OutputJSON, "select profile", err)
	}
	if command.OutputJSON {
		if err := a.writeJSON(profileShowOutput{
			SchemaVersion: "1",
			SourcePath:    info.SourcePath,
			Profile:       profile,
		}); err != nil {
			a.stderrf("agent-secret: write profile show json: %v\n", err)
			return 1
		}
		return 0
	}
	writer := tabwriter.NewWriter(a.Stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(writer, "config:\t%s\n", info.SourcePath); err != nil {
		return a.profileWriteError(err)
	}
	if _, err := fmt.Fprintf(writer, "profile:\t%s\n", profile.Name); err != nil {
		return a.profileWriteError(err)
	}
	if profile.Default {
		if _, err := fmt.Fprintln(writer, "default:\ttrue"); err != nil {
			return a.profileWriteError(err)
		}
	}
	if profile.Account != "" {
		if _, err := fmt.Fprintf(writer, "account:\t%s\n", profile.Account); err != nil {
			return a.profileWriteError(err)
		}
	}
	if profile.Reason != "" {
		if _, err := fmt.Fprintf(writer, "reason:\t%s\n", profile.Reason); err != nil {
			return a.profileWriteError(err)
		}
	}
	if profile.TTL != "" {
		if _, err := fmt.Fprintf(writer, "ttl:\t%s\n", profile.TTL); err != nil {
			return a.profileWriteError(err)
		}
	}
	if len(profile.Include) > 0 {
		if _, err := fmt.Fprintf(writer, "include:\t%s\n", joinComma(profile.Include)); err != nil {
			return a.profileWriteError(err)
		}
	}
	if profile.Session != nil && profile.Session.Bind != nil {
		if _, err := fmt.Fprintf(writer, "session_bind:\t%s\n", sessionBindingPolicyText(*profile.Session.Bind)); err != nil {
			return a.profileWriteError(err)
		}
	}
	if _, err := fmt.Fprintln(writer, "secrets:"); err != nil {
		return a.profileWriteError(err)
	}
	for _, secret := range profile.Secrets {
		account := secret.Account
		if account == "" {
			account = "(default desktop account)"
		}
		if _, err := fmt.Fprintf(writer, "  %s\t%s\t%s\n", secret.Alias, secret.Ref, account); err != nil {
			return a.profileWriteError(err)
		}
	}
	return a.profileWriteError(writer.Flush())
}

func selectProfile(info profileconfig.ConfigInfo, name string) (profileconfig.ProfileInfo, error) {
	if name == "" {
		name = info.DefaultProfile
	}
	if name == "" {
		return profileconfig.ProfileInfo{}, fmt.Errorf("%w: default_profile is required when no profile name is provided", profileconfig.ErrProfileNotFound)
	}
	for _, profile := range info.Profiles {
		if profile.Name == name {
			return profile, nil
		}
	}
	return profileconfig.ProfileInfo{}, fmt.Errorf("%w: %q; valid profiles: %s", profileconfig.ErrProfileNotFound, name, validProfileNames(info))
}

func validProfileNames(info profileconfig.ConfigInfo) string {
	names := make([]string, 0, len(info.Profiles))
	for _, profile := range info.Profiles {
		names = append(names, profile.Name)
	}
	return joinComma(names)
}

func joinComma(values []string) string {
	var out strings.Builder
	for index, value := range values {
		if index > 0 {
			out.WriteString(", ")
		}
		out.WriteString(value)
	}
	return out.String()
}

func sessionBindingPolicyText(policy request.SessionBindingPolicy) string {
	switch policy.Mode {
	case request.SessionBindingModeAuto, "":
		return "auto"
	case request.SessionBindingModeAncestor:
		if policy.AncestorDepth == 1 {
			return "parent"
		}
		return fmt.Sprintf("ancestor:%d", policy.AncestorDepth)
	case request.SessionBindingModeAncestorName:
		if len(policy.AncestorNames) > 1 {
			return "ancestor_names:" + strings.Join(policy.AncestorNames, ",")
		}
		return "ancestor_name:" + policy.AncestorName
	default:
		return string(policy.Mode)
	}
}

func (a App) profileError(jsonOutput bool, context string, err error) int {
	if jsonOutput {
		return a.writeJSONError(context, err)
	}
	if errors.Is(err, profileconfig.ErrConfigNotFound) {
		a.stderrf("agent-secret: %s: %v\n", context, err)
		return 2
	}
	a.stderrf("agent-secret: %s: %v\n", context, err)
	return 1
}

func (a App) profileWriteError(err error) int {
	if err != nil {
		a.stderrf("agent-secret: write profile output: %v\n", err)
		return 1
	}
	return 0
}
