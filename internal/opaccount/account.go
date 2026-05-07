package opaccount

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

const DefaultDesktopAccount = "my.1password.com"

type cliAccount struct {
	URL         string `json:"url"`
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand"`
	AccountUUID string `json:"account_uuid"`
}

func SelectDesktopAccount(accountOverride string, opAccount string) string {
	return SelectDesktopAccountWithDetector(accountOverride, opAccount, DetectSingleCLIAccount)
}

func SelectDesktopAccountWithDetector(
	accountOverride string,
	opAccount string,
	detectSingleAccount func() string,
) string {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account
	}
	if account := strings.TrimSpace(opAccount); account != "" {
		return account
	}
	if detectSingleAccount != nil {
		if account := strings.TrimSpace(detectSingleAccount()); account != "" {
			return account
		}
	}
	return DefaultDesktopAccount
}

func DetectSingleCLIAccount() string {
	opPath, err := exec.LookPath("op")
	if err != nil {
		return ""
	}
	if account := detectSingleCLIAccountJSON(opPath); account != "" {
		return account
	}
	return detectSingleCLIAccountTable(opPath)
}

func detectSingleCLIAccountJSON(opPath string) string {
	output, err := runOPAccountList(opPath, "--format=json")
	if err != nil {
		return ""
	}
	return singleCLIAccountFromJSON(output)
}

func singleCLIAccountFromJSON(output []byte) string {
	var accounts []cliAccount
	if err := json.Unmarshal(output, &accounts); err != nil {
		return ""
	}

	return singleAccountName(accounts, func(account cliAccount) string {
		for _, candidate := range []string{account.URL, account.Name, account.Shorthand, account.AccountUUID} {
			if value := strings.TrimSpace(candidate); value != "" {
				return value
			}
		}
		return ""
	})
}

func detectSingleCLIAccountTable(opPath string) string {
	output, err := runOPAccountList(opPath)
	if err != nil {
		return ""
	}
	return singleCLIAccountFromTable(output)
}

func singleCLIAccountFromTable(output []byte) string {
	var accounts []string
	for line := range strings.SplitSeq(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "URL ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		accounts = append(accounts, fields[0])
	}
	if len(accounts) != 1 {
		return ""
	}
	return accounts[0]
}

func singleAccountName[T any](accounts []T, name func(T) string) string {
	var selected string
	count := 0
	for _, account := range accounts {
		candidate := strings.TrimSpace(name(account))
		if candidate == "" {
			continue
		}
		selected = candidate
		count++
	}
	if count != 1 {
		return ""
	}
	return selected
}

func runOPAccountList(opPath string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	commandArgs := append([]string{"account", "list"}, args...)
	return exec.CommandContext(ctx, opPath, commandArgs...).Output() //nolint:gosec // G204: opPath is the user's 1Password CLI and this command reads only account metadata.
}
