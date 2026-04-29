package opresolver

import (
	"context"
	"os"
	"strings"
)

const DefaultDesktopAccount = "my.1password.com"

func desktopAccount(ctx context.Context, accountOverride string) (string, error) {
	return desktopAccountWith(ctx, accountOverride, os.Getenv("OP_ACCOUNT"))
}

func desktopAccountWith(
	_ context.Context,
	accountOverride string,
	opAccount string,
) (string, error) {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account, nil
	}
	if account := strings.TrimSpace(opAccount); account != "" {
		return account, nil
	}
	return DefaultDesktopAccount, nil
}
