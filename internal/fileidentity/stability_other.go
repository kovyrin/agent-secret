//go:build !unix

package fileidentity

import "fmt"

func ValidateStableExecutable(path string) error {
	return fmt.Errorf("executable stability checks are unsupported on this platform: %s", path)
}
