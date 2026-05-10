//go:build darwin && cgo

package opaccount

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDetectDefaultDesktopAccountFromSQLitePrefersPersonalAccount(t *testing.T) {
	dbPath := createDesktopAccountsDB(t, []DesktopAccount{
		{
			UUID:      "BusinessUUID",
			State:     "A",
			UserState: "A",
			Type:      "B",
			SignInURL: "https://fixture.1password.com/",
		},
		{
			UUID:      "PersonalUUID",
			State:     "A",
			UserState: "A",
			Type:      "F",
			SignInURL: "https://my.1password.com/",
		},
	})

	got := detectDefaultDesktopAccountFromSQLite(dbPath)
	if got != "PersonalUUID" {
		t.Fatalf("account = %q, want personal account", got)
	}
}

func TestDetectDefaultDesktopAccountFromSQLiteFallsBackToSingleAccount(t *testing.T) {
	dbPath := createDesktopAccountsDB(t, []DesktopAccount{
		{
			UUID:      "BusinessUUID",
			State:     "A",
			UserState: "A",
			Type:      "B",
			SignInURL: "https://fixture.1password.com/",
		},
	})

	got := detectDefaultDesktopAccountFromSQLite(dbPath)
	if got != "BusinessUUID" {
		t.Fatalf("account = %q, want only active account", got)
	}
}

func TestDetectDefaultDesktopAccountFromSQLiteRejectsAmbiguousAccounts(t *testing.T) {
	dbPath := createDesktopAccountsDB(t, []DesktopAccount{
		{UUID: "BusinessOne", State: "A", UserState: "A", Type: "B"},
		{UUID: "BusinessTwo", State: "A", UserState: "A", Type: "B"},
	})

	got := detectDefaultDesktopAccountFromSQLite(dbPath)
	if got != "" {
		t.Fatalf("account = %q, want no default account", got)
	}
}

func TestDetectDefaultDesktopAccountFromSQLiteReturnsBlankForMissingTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "1password.sqlite")
	runSQLite(t, dbPath, "CREATE TABLE unrelated (value TEXT);")

	got := detectDefaultDesktopAccountFromSQLite(dbPath)
	if got != "" {
		t.Fatalf("account = %q, want no default account", got)
	}
}

func createDesktopAccountsDB(t *testing.T, accounts []DesktopAccount) string {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "1password.sqlite")
	runSQLite(t, dbPath, `
		CREATE TABLE accounts (
			account_uuid TEXT PRIMARY KEY NOT NULL,
			data BLOB NOT NULL
		);
	`)
	for _, account := range accounts {
		runSQLite(t, dbPath, `
			INSERT INTO accounts (account_uuid, data)
			VALUES (`+sqliteQuote(account.UUID)+`, json(`+sqliteQuote(desktopAccountJSON(account))+`));
		`)
	}
	return dbPath
}

func desktopAccountJSON(account DesktopAccount) string {
	return `{"account_state":` + jsonString(account.State) +
		`,"user_state":` + jsonString(account.UserState) +
		`,"account_type":` + jsonString(account.Type) +
		`,"sign_in_url":` + jsonString(account.SignInURL) + `}`
}

func jsonString(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func sqliteQuote(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}

func runSQLite(t *testing.T, dbPath string, query string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/sqlite3", dbPath, query) //nolint:gosec // G204: test setup uses fixed system sqlite3 with generated temp DB input.
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sqlite3 failed: %v\n%s", err, output)
	}
}
