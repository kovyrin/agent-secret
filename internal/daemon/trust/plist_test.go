package trust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlistString(t *testing.T) {
	t.Parallel()

	errKind := errors.New("plist fixture")
	tests := []struct {
		name    string
		body    string
		key     string
		want    string
		wantErr string
	}{
		{
			name: "returns matching string value",
			body: `
<plist>
  <dict>
    <key>Ignored</key>
    <string>ignored-value</string>
    <key>CFBundleIdentifier</key>
    <string>com.kovyrin.agent-secret</string>
  </dict>
</plist>`,
			key:  "CFBundleIdentifier",
			want: "com.kovyrin.agent-secret",
		},
		{
			name: "missing key",
			body: `
<plist>
  <dict>
    <key>CFBundleName</key>
    <string>Agent Secret</string>
  </dict>
</plist>`,
			key:     "CFBundleIdentifier",
			wantErr: "missing CFBundleIdentifier",
		},
		{
			name:    "malformed key",
			body:    `<plist><dict><key>CFBundleIdentifier`,
			key:     "CFBundleIdentifier",
			wantErr: "parse",
		},
		{
			name:    "malformed string",
			body:    `<plist><dict><key>CFBundleIdentifier</key><string>com.kovyrin.agent-secret`,
			key:     "CFBundleIdentifier",
			wantErr: "parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := writePlistFixture(t, tt.body)
			got, err := PlistString(path, tt.key, errKind)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("PlistString returned nil error")
				}
				if !errors.Is(err, errKind) {
					t.Fatalf("error = %v, want wrapped %v", err, errKind)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("PlistString returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("PlistString = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPlistStringWrapsReadError(t *testing.T) {
	t.Parallel()

	errKind := errors.New("plist fixture")
	path := filepath.Join(t.TempDir(), "missing.plist")

	_, err := PlistString(path, "CFBundleIdentifier", errKind)
	if err == nil {
		t.Fatal("PlistString returned nil error")
	}
	if !errors.Is(err, errKind) {
		t.Fatalf("error = %v, want wrapped %v", err, errKind)
	}
	if !strings.Contains(err.Error(), "read "+path) {
		t.Fatalf("error = %v, want read path context", err)
	}
}

func writePlistFixture(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "Info.plist")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write plist fixture: %v", err)
	}
	return path
}
