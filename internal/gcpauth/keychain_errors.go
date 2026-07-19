package gcpauth

import "fmt"

const (
	keychainStatusUserCanceled            = -128
	keychainStatusAuthFailed              = -25293
	keychainStatusInteractionNotAllowed   = -25308
	keychainStatusUserInteractionRequired = -25315
)

func keychainStatusErrorFromStatus(operation string, status int) error {
	if isKeychainInteractionStatus(status) {
		return fmt.Errorf(
			"%w: macOS refused non-interactive Keychain %s for Agent Secret GCP OAuth state; run `agent-secret gcp auth logout --google-account ALIAS` and `agent-secret gcp auth login --google-account ALIAS` with the current Agent Secret app build",
			ErrKeychainAccess,
			operation,
		)
	}
	return fmt.Errorf("GCP Keychain %s failed with OSStatus %d", operation, status)
}

func isKeychainInteractionStatus(status int) bool {
	switch status {
	case keychainStatusUserCanceled, keychainStatusAuthFailed, keychainStatusInteractionNotAllowed, keychainStatusUserInteractionRequired:
		return true
	default:
		return false
	}
}
