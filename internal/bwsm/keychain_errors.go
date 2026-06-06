package bwsm

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
			"%w: macOS refused non-interactive Keychain %s for Agent Secret Bitwarden Secrets Manager tokens; reinstall the token with `agent-secret bitwarden secrets-manager token install --alias ALIAS`",
			ErrKeychainAccess,
			operation,
		)
	}
	return fmt.Errorf("bitwarden Secrets Manager Keychain %s failed with OSStatus %d", operation, status)
}

func isKeychainInteractionStatus(status int) bool {
	switch status {
	case keychainStatusUserCanceled, keychainStatusAuthFailed, keychainStatusInteractionNotAllowed, keychainStatusUserInteractionRequired:
		return true
	default:
		return false
	}
}
