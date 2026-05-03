//go:build darwin

package peercred

import "testing"

func TestInspectFDRejectsInvalidDescriptor(t *testing.T) {
	t.Parallel()

	_, err := inspectFD(^uintptr(0))
	if err == nil {
		t.Fatal("expected invalid descriptor error")
	}
}
