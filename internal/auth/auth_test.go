package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns api key when header correct", func(t *testing.T) {
		h := http.Header{}
		h.Set("Authorization", "ApiKey my-secret")
		got, err := GetAPIKey(h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "my-secret" {
			t.Fatalf("expected %q, got %q", "my-secret", got)
		}
	})

	t.Run("missing header returns ErrNoAuthHeaderIncluded", func(t *testing.T) {
		h := http.Header{}
		got, err := GetAPIKey(h)
		if got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("wrong scheme returns malformed error", func(t *testing.T) {
		h := http.Header{}
		h.Set("Authorization", "Bearer token")
		got, err := GetAPIKey(h)
		if got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
		if err == nil || err.Error() != "malformed authorization header" {
			t.Fatalf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("api key with trailing space returns empty key", func(t *testing.T) {
		h := http.Header{}
		h.Set("Authorization", "ApiKey ")
		got, err := GetAPIKey(h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("expected empty api key, got %q", got)
		}
	})

	t.Run("api key with extra parts returns first token", func(t *testing.T) {
		h := http.Header{}
		h.Set("Authorization", "ApiKey token extra")
		got, err := GetAPIKey(h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "token" {
			t.Fatalf("expected %q, got %q", "token", got)
		}
	})
}
