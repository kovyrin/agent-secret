package daemon

import (
	"errors"
	"fmt"
	"os"

	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

var ErrExecutableChanged = errors.New("daemon executable changed on disk")

func CurrentExecutableSelfCheck() (func() error, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve daemon executable: %w", err)
	}
	identity, err := fileidentity.Capture(path)
	if err != nil {
		return nil, fmt.Errorf("capture daemon executable identity: %w", err)
	}
	return NewExecutableSelfCheck(path, identity), nil
}

func NewExecutableSelfCheck(path string, expected fileidentity.Identity) func() error {
	return func() error {
		if expected.IsZero() {
			return fmt.Errorf("%w: startup executable identity is missing", ErrExecutableChanged)
		}
		actual, err := fileidentity.Capture(path)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrExecutableChanged, err)
		}
		if actual != expected {
			return fmt.Errorf("%w: executable %q no longer matches startup identity", ErrExecutableChanged, path)
		}
		return nil
	}
}
