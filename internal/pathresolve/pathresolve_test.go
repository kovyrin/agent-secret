package pathresolve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictResolvesSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	got, err := Strict(link)
	if err != nil {
		t.Fatalf("Strict returned error: %v", err)
	}
	want, err := Strict(target)
	if err != nil {
		t.Fatalf("Strict target returned error: %v", err)
	}
	if got != want {
		t.Fatalf("Strict path = %q, want %q", got, want)
	}
}

func TestStrictRejectsBrokenSymlink(t *testing.T) {
	t.Parallel()

	link := filepath.Join(t.TempDir(), "broken")
	if err := os.Symlink("missing", link); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	_, err := Strict(link)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Strict error = %v, want os.ErrNotExist", err)
	}
}

func TestBestEffortFallsBackToAbsolutePath(t *testing.T) {
	t.Parallel()

	link := filepath.Join(t.TempDir(), "broken")
	if err := os.Symlink("missing", link); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}

	got := BestEffort(link)
	if got != link {
		t.Fatalf("BestEffort path = %q, want unresolved absolute path %q", got, link)
	}
}
