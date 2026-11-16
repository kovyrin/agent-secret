//go:build !unix

package installgate

import (
	"errors"
	"os"
)

func AcquireForExecutable() (*os.File, error) { return nil, nil }

func HostBundle(string) string { return "" }

func TransactionPresent(string) bool { return false }

func RequireCaskLease() (*os.File, error) {
	return nil, errors.New("Homebrew postflight requires macOS")
}
