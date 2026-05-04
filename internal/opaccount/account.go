package opaccount

import "strings"

const DefaultDesktopAccount = "my.1password.com"

func SelectDesktopAccount(accountOverride string, opAccount string) string {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account
	}
	if account := strings.TrimSpace(opAccount); account != "" {
		return account
	}
	return DefaultDesktopAccount
}
