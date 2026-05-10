//go:build darwin && cgo

package opaccount

/*
#cgo darwin LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"path/filepath"
	"unsafe"
)

const desktopAccountQuery = `
SELECT
	account_uuid,
	json_extract(data, '$.account_state'),
	json_extract(data, '$.user_state'),
	json_extract(data, '$.account_type'),
	json_extract(data, '$.sign_in_url')
FROM accounts
ORDER BY account_uuid`

const sqliteOK = 0

func DetectDefaultDesktopAccount() string {
	path, err := desktopAccountsDBPath()
	if err != nil {
		return ""
	}
	return detectDefaultDesktopAccountFromSQLite(path)
}

func desktopAccountsDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(
		home,
		"Library",
		"Group Containers",
		"2BUA8C4S2C.com.1password",
		"Library",
		"Application Support",
		"1Password",
		"Data",
		"1password.sqlite",
	), nil
}

func detectDefaultDesktopAccountFromSQLite(path string) string {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var db *C.sqlite3
	flags := C.int(C.SQLITE_OPEN_READONLY | C.SQLITE_OPEN_NOMUTEX)
	//nolint:gocritic // cgo SQLite return-code comparisons confuse dupSubExpr.
	if int(C.sqlite3_open_v2(cPath, &db, flags, nil)) != sqliteOK {
		if db != nil {
			C.sqlite3_close(db)
		}
		return ""
	}
	defer C.sqlite3_close(db)

	cQuery := C.CString(desktopAccountQuery)
	defer C.free(unsafe.Pointer(cQuery))

	var stmt *C.sqlite3_stmt
	//nolint:gocritic // cgo SQLite return-code comparisons confuse dupSubExpr.
	if int(C.sqlite3_prepare_v2(db, cQuery, -1, &stmt, nil)) != sqliteOK {
		return ""
	}
	defer C.sqlite3_finalize(stmt)

	var accounts []DesktopAccount
	for {
		switch rc := C.sqlite3_step(stmt); rc {
		case C.SQLITE_ROW:
			accounts = append(accounts, DesktopAccount{
				UUID:      sqliteColumnText(stmt, 0),
				State:     sqliteColumnText(stmt, 1),
				UserState: sqliteColumnText(stmt, 2),
				Type:      sqliteColumnText(stmt, 3),
				SignInURL: sqliteColumnText(stmt, 4),
			})
		case C.SQLITE_DONE:
			return SelectDefaultDesktopAccount(accounts)
		default:
			return ""
		}
	}
}

func sqliteColumnText(stmt *C.sqlite3_stmt, column int) string {
	text := C.sqlite3_column_text(stmt, C.int(column))
	if text == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(text)))
}
