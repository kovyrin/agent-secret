package trust

import "testing"

func TestDefaultExpectedTeamIDUsesBuildConfiguredTeamID(t *testing.T) {
	previous := defaultDeveloperIDTeamID
	defaultDeveloperIDTeamID = " B6L7QLWTZW "
	t.Cleanup(func() {
		defaultDeveloperIDTeamID = previous
	})

	if got := DefaultExpectedTeamID(); got != "B6L7QLWTZW" {
		t.Fatalf("DefaultExpectedTeamID = %q, want configured Developer ID Team ID", got)
	}
}
