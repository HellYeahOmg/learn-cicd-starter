package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("Valid API key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey test-api-key-123")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		expected := "test-api-key-123"
		if apiKey != expected {
			t.Errorf("Expected API key %q, got %q", expected, apiKey)
		}
	})

	t.Run("Missing authorization header", func(t *testing.T) {
		headers := http.Header{}

		apiKey, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}

		if apiKey != "" {
			t.Errorf("Expected empty API key, got %q", apiKey)
		}
	})

	t.Run("Malformed authorization header - wrong scheme", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer test-token")

		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}

		expectedErrMsg := "malformed authorization header"
		if err.Error() != expectedErrMsg {
			t.Errorf("Expected error message %q, got %q", expectedErrMsg, err.Error())
		}

		if apiKey != "" {
			t.Errorf("Expected empty API key, got %q", apiKey)
		}
	})

	t.Run("Malformed authorization header - missing key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		apiKey, err := GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error for malformed header, got nil")
		}

		expectedErrMsg := "malformed authorization header"
		if err.Error() != expectedErrMsg {
			t.Errorf("Expected error message %q, got %q", expectedErrMsg, err.Error())
		}

		if apiKey != "" {
			t.Errorf("Expected empty API key, got %q", apiKey)
		}
	})
}