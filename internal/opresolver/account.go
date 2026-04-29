package opresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type cliAccount struct {
	AccountUUID string `json:"account_uuid"`
	URL         string `json:"url"`
}

type accountListFunc func(context.Context) ([]byte, error)

func opAccountList(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "op", "account", "list", "--format", "json").Output()
}

func desktopAccount(ctx context.Context, accountOverride string) (string, error) {
	return desktopAccountWith(ctx, accountOverride, os.Getenv("OP_ACCOUNT"), opAccountList)
}

func desktopAccountWith(
	ctx context.Context,
	accountOverride string,
	opAccount string,
	listAccounts accountListFunc,
) (string, error) {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account, nil
	}
	if account := strings.TrimSpace(opAccount); account != "" {
		return account, nil
	}

	account, err := defaultDesktopAccountWith(ctx, listAccounts)
	if err != nil {
		return "", fmt.Errorf("discover default 1Password account: %w", err)
	}
	return account, nil
}

func defaultDesktopAccountWith(ctx context.Context, listAccounts accountListFunc) (string, error) {
	out, err := listAccounts(ctx)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("1Password CLI not found; install op, set OP_ACCOUNT, or set AGENT_SECRET_1PASSWORD_ACCOUNT")
		}
		return "", fmt.Errorf("run op account list: %w", err)
	}

	account, err := firstAccountUUID(out)
	if err != nil {
		return "", err
	}
	return account, nil
}

func firstAccountUUID(data []byte) (string, error) {
	var accounts []cliAccount
	if err := json.Unmarshal(data, &accounts); err != nil {
		return "", fmt.Errorf("parse op account list: %w", err)
	}

	for _, account := range accounts {
		if uuid := strings.TrimSpace(account.AccountUUID); uuid != "" {
			return uuid, nil
		}
	}
	return "", errors.New("op account list returned no accounts; sign in with 1Password CLI, set OP_ACCOUNT, or set AGENT_SECRET_1PASSWORD_ACCOUNT")
}
