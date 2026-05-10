package opaccount

import (
	"net/url"
	"strings"
)

const DefaultDesktopAccount = ""

type DesktopAccount struct {
	UUID      string
	State     string
	UserState string
	Type      string
	SignInURL string
}

func SelectDesktopAccount(accountOverride string, opAccount string) string {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account
	}
	if account := strings.TrimSpace(opAccount); account != "" {
		return account
	}
	return DefaultDesktopAccount
}

func SelectDefaultDesktopAccount(accounts []DesktopAccount) string {
	activeAccounts := activeDesktopAccounts(accounts)
	if account := selectDesktopAccount(activeAccounts, isPersonalSignInURLAccount); account != "" {
		return account
	}
	if account := selectDesktopAccount(activeAccounts, isPersonalTypeAccount); account != "" {
		return account
	}
	return selectSingleDesktopAccount(activeAccounts)
}

func activeDesktopAccounts(accounts []DesktopAccount) []DesktopAccount {
	var active []DesktopAccount
	for _, account := range accounts {
		account.UUID = strings.TrimSpace(account.UUID)
		if account.UUID == "" {
			continue
		}
		if state := strings.TrimSpace(account.State); state != "" && !strings.EqualFold(state, "A") {
			continue
		}
		if userState := strings.TrimSpace(account.UserState); userState != "" && !strings.EqualFold(userState, "A") {
			continue
		}
		active = append(active, account)
	}
	return active
}

func selectDesktopAccount(accounts []DesktopAccount, match func(DesktopAccount) bool) string {
	var selected string
	count := 0
	for _, account := range accounts {
		if !match(account) {
			continue
		}
		selected = account.UUID
		count++
	}
	if count != 1 {
		return ""
	}
	return selected
}

func selectSingleDesktopAccount(accounts []DesktopAccount) string {
	var accountUUIDs []string
	for _, account := range accounts {
		accountUUIDs = append(accountUUIDs, account.UUID)
	}
	return selectSingleAccount(accountUUIDs)
}

func isPersonalSignInURLAccount(account DesktopAccount) bool {
	signInURL := strings.TrimSpace(account.SignInURL)
	if signInURL == "" {
		return false
	}
	parsed, err := url.Parse(signInURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Hostname(), "my.1password.com")
}

func isPersonalTypeAccount(account DesktopAccount) bool {
	switch strings.ToUpper(strings.TrimSpace(account.Type)) {
	case "F", "I", "P":
		return true
	default:
		return false
	}
}

func selectSingleAccount(accounts []string) string {
	var selected string
	count := 0
	for _, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" {
			continue
		}
		selected = account
		count++
	}
	if count != 1 {
		return ""
	}
	return selected
}
