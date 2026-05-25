//go:build !darwin

package gcpauth

import (
	"context"
	"errors"
)

func OpenBrowser(context.Context, string) error {
	return errors.New("browser launch is only implemented on macOS")
}
