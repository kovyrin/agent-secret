package buildinfo

import "testing"

func TestDisplayVersion(t *testing.T) {
	originalVersion := Version
	originalRevision := Revision
	t.Cleanup(func() {
		Version = originalVersion
		Revision = originalRevision
	})

	tests := []struct {
		name     string
		version  string
		revision string
		want     string
	}{
		{
			name:    "version only",
			version: "0.0.8-dev",
			want:    "agent-secret 0.0.8-dev",
		},
		{
			name:     "version with revision",
			version:  "0.0.8",
			revision: "abc123",
			want:     "agent-secret 0.0.8 (abc123)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Version = tt.version
			Revision = tt.revision

			if got := DisplayVersion(); got != tt.want {
				t.Fatalf("DisplayVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
