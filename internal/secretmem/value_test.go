package secretmem

import (
	"errors"
	"testing"
)

func TestValueRoundTrip(t *testing.T) {
	t.Parallel()

	value, err := New("super-secret")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := value.Destroy(); err != nil {
			t.Fatalf("Destroy returned error: %v", err)
		}
	})

	got, err := value.Reveal()
	if err != nil {
		t.Fatalf("Reveal returned error: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("Reveal = %q, want super-secret", got)
	}
}

func TestValueSupportsEmptySecret(t *testing.T) {
	t.Parallel()

	value, err := New("")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := value.Destroy(); err != nil {
			t.Fatalf("Destroy returned error: %v", err)
		}
	})

	got, err := value.Reveal()
	if err != nil {
		t.Fatalf("Reveal returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("Reveal = %q, want empty string", got)
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	t.Parallel()

	value, err := New("super-secret")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if err := value.Destroy(); err != nil {
		t.Fatalf("first Destroy returned error: %v", err)
	}
	if err := value.Destroy(); err != nil {
		t.Fatalf("second Destroy returned error: %v", err)
	}
	if _, err := value.Reveal(); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Reveal after Destroy error = %v, want ErrDestroyed", err)
	}
}
