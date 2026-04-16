package httpclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOAuth2Authenticator(t *testing.T) {
	clientID := "test-client-id"
	clientSecret := "test-client-secret"
	token := "test-bearer-token"

	// Mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request to token URL, got %v", r.Method)
		}

		// In a real client credentials flow, we would check basic auth or form values
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "` + token + `", "token_type": "Bearer", "expires_in": 3600}`))
	}))
	defer tokenServer.Close()

	// Mock API server
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + token
		if gotAuth != expectedAuth {
			t.Errorf("expected Auth header %q, got %q", expectedAuth, gotAuth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	auth := NewOAuth2Authenticator(clientID, clientSecret, tokenServer.URL, nil)
	client := NewClientBuilder().
		WithTimeout(5 * time.Second).
		WithAuthenticator(auth).
		Build()

	resp, err := client.Get(apiServer.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

func TestOAuth2AuthenticatorFailure(t *testing.T) {
	// Mock token server that returns an error
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	auth := NewOAuth2Authenticator("id", "secret", tokenServer.URL, nil)
	client := NewClientBuilder().
		WithTimeout(5 * time.Second).
		WithAuthenticator(auth).
		Build()

	_, err := client.Get("http://example.com")
	if err == nil {
		t.Error("expected error on token fetch failure")
	}
}

func TestOAuth2AuthenticatorWithInsecureTLS(t *testing.T) {
	token := "tls-bearer-token"

	// Self-signed cert token server — would fail without InsecureSkipVerify
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%s", "token_type": "Bearer", "expires_in": 3600}`, token)
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	auth := NewOAuth2Authenticator("id", "secret", tokenServer.URL+"/token", nil)
	client := NewClientBuilder().
		WithTimeout(5 * time.Second).
		WithTLS(&TLSConfig{InsecureSkipVerify: true}).
		WithAuthenticator(auth).
		Build()

	resp, err := client.Get(apiServer.URL)
	if err != nil {
		t.Fatalf("token fetch failed TLS verification: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %v", resp.Status)
	}
}
