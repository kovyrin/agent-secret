package gcpauth

import (
	"errors"
	"strings"
	"testing"
)

func TestKeychainStatusErrorMapsInteractiveStatuses(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		keychainStatusUserCanceled,
		keychainStatusAuthFailed,
		keychainStatusInteractionNotAllowed,
		keychainStatusUserInteractionRequired,
	} {
		err := keychainStatusErrorFromStatus("read", status)
		if !errors.Is(err, ErrKeychainAccess) {
			t.Fatalf("status %d error = %v, want ErrKeychainAccess", status, err)
		}
		if strings.Contains(err.Error(), "OSStatus") {
			t.Fatalf("status %d error exposed raw OSStatus: %v", status, err)
		}
		if !strings.Contains(err.Error(), "gcp auth logout") || !strings.Contains(err.Error(), "gcp auth login") {
			t.Fatalf("status %d error lacks repair guidance: %v", status, err)
		}
	}
}

func TestKeychainStatusErrorPreservesUnexpectedStatus(t *testing.T) {
	t.Parallel()

	err := keychainStatusErrorFromStatus("write", -50)
	if errors.Is(err, ErrKeychainAccess) {
		t.Fatalf("unexpected status mapped to ErrKeychainAccess: %v", err)
	}
	if !strings.Contains(err.Error(), "OSStatus -50") {
		t.Fatalf("unexpected status error = %v", err)
	}
}
