package approval

import (
	"errors"
	"testing"
)

func TestDenialErrorPreservesApprovalDeniedSentinel(t *testing.T) {
	t.Parallel()

	err := DenialError(DenialReasonComputerLocked)
	if !errors.Is(err, ErrApprovalDenied) {
		t.Fatalf("DenialError is not ErrApprovalDenied: %v", err)
	}
	if got, want := err.Error(), "Denied: Computer is locked, human approval is impossible"; got != want {
		t.Fatalf("DenialError message = %q, want %q", got, want)
	}
}
