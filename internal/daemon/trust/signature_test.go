package trust

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

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

func TestTeamIDFromCodesignOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		output  string
		want    string
		wantErr string
	}{
		{
			name: "sanitized fixture",
			output: strings.Join([]string{
				"Executable=/Applications/Agent Secret.app/Contents/MacOS/Agent Secret",
				"Identifier=com.kovyrin.agent-secret",
				"Format=app bundle with Mach-O thin (arm64)",
				"CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=25+7 location=embedded",
				"TeamIdentifier=B6L7QLWTZW",
				"Runtime Version=15.0.0",
			}, "\n"),
			want: "B6L7QLWTZW",
		},
		{
			name: "trims value",
			output: strings.Join([]string{
				"Identifier=com.kovyrin.agent-secret",
				"TeamIdentifier= B6L7QLWTZW ",
			}, "\n"),
			want: "B6L7QLWTZW",
		},
		{
			name: "missing",
			output: strings.Join([]string{
				"Identifier=com.kovyrin.agent-secret",
				"Runtime Version=15.0.0",
			}, "\n"),
			wantErr: "missing TeamIdentifier",
		},
		{
			name:    "empty",
			output:  "TeamIdentifier= \n",
			wantErr: "empty TeamIdentifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := teamIDFromCodesignOutput([]byte(tt.output))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("teamIDFromCodesignOutput returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("team id = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifyCodeSignatureTargetWithRunner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		verifyOutput  []byte
		verifyErr     error
		inspectOutput []byte
		inspectErr    error
		wantTeamID    string
		wantErr       string
		wantCalls     [][]string
	}{
		{
			name:          "returns parsed team id",
			inspectOutput: []byte("Identifier=com.kovyrin.agent-secret\nTeamIdentifier=B6L7QLWTZW\n"),
			wantTeamID:    "B6L7QLWTZW",
			wantCalls: [][]string{
				{"--verify", "--strict", "--deep", "/Applications/Agent Secret.app"},
				{"-dv", "--verbose=4", "/Applications/Agent Secret.app"},
			},
		},
		{
			name:      "verify failure",
			verifyErr: errors.New("signature rejected"),
			wantErr:   "verify code signature for fixture",
			wantCalls: [][]string{
				{"--verify", "--strict", "--deep", "/Applications/Agent Secret.app"},
			},
		},
		{
			name:         "verify failure includes codesign output",
			verifyOutput: []byte("+64264: No such process\n"),
			verifyErr:    errors.New("exit status 1"),
			wantErr:      "+64264: No such process",
			wantCalls: [][]string{
				{"--verify", "--strict", "--deep", "/Applications/Agent Secret.app"},
			},
		},
		{
			name:       "inspect failure",
			inspectErr: errors.New("inspect failed"),
			wantErr:    "inspect code signature for fixture",
			wantCalls: [][]string{
				{"--verify", "--strict", "--deep", "/Applications/Agent Secret.app"},
				{"-dv", "--verbose=4", "/Applications/Agent Secret.app"},
			},
		},
		{
			name:          "missing team id",
			inspectOutput: []byte("Identifier=com.kovyrin.agent-secret\n"),
			wantErr:       "missing TeamIdentifier",
			wantCalls: [][]string{
				{"--verify", "--strict", "--deep", "/Applications/Agent Secret.app"},
				{"-dv", "--verbose=4", "/Applications/Agent Secret.app"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runner := &recordingCodesignRunner{
				verifyOutput:  tt.verifyOutput,
				verifyErr:     tt.verifyErr,
				inspectOutput: tt.inspectOutput,
				inspectErr:    tt.inspectErr,
			}
			got, err := verifyCodeSignatureTargetWithRunner(
				context.Background(),
				"/Applications/Agent Secret.app",
				"code signature for fixture",
				runner.run,
			)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("verifyCodeSignatureTargetWithRunner returned error: %v", err)
			}
			if got != tt.wantTeamID {
				t.Fatalf("team id = %q, want %q", got, tt.wantTeamID)
			}
			if !equalStringSlices(runner.calls, tt.wantCalls) {
				t.Fatalf("codesign calls = %q, want %q", runner.calls, tt.wantCalls)
			}
		})
	}
}

type recordingCodesignRunner struct {
	verifyOutput  []byte
	verifyErr     error
	inspectOutput []byte
	inspectErr    error
	calls         [][]string
}

func (r *recordingCodesignRunner) run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, slices.Clone(args))
	if len(args) > 0 && args[0] == "--verify" {
		return r.verifyOutput, r.verifyErr
	}
	return r.inspectOutput, r.inspectErr
}

func equalStringSlices(got [][]string, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !slices.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}
