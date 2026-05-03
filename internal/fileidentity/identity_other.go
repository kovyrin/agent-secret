//go:build !unix

package fileidentity

import "os"

func addPlatformIdentity(_ *Identity, _ os.FileInfo) error {
	return nil
}
