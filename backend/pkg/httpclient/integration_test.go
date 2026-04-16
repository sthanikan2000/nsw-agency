package httpclient

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClientBuilder tests the ClientBuilder fluent API
func TestClientBuilder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientBuilder().
		WithBaseURL(server.URL).
		WithTimeout(5 * time.Second).
		Build()

	if client.BaseURL != server.URL+"/" {
		t.Errorf("expected base URL %q, got %q", server.URL+"/", client.BaseURL)
	}

	resp, err := client.Get("/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestClientBuilderWithAuthenticator tests the builder with an authenticator
func TestClientBuilderWithAuthenticator(t *testing.T) {
	expectedAPIKey := "test-api-key"

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("X-API-Key")
		if auth != expectedAPIKey {
			t.Errorf("expected API key %q, got %q", expectedAPIKey, auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	apiKeyAuth := NewAPIKeyAuthenticator(expectedAPIKey, "X-API-Key")
	client := NewClientBuilder().
		WithBaseURL(apiServer.URL).
		WithAuthenticator(apiKeyAuth).
		Build()

	resp, err := client.Get("/api/data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestClientBuilderWithTLS tests the builder with TLS configuration
func TestClientBuilderWithTLS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tlsConfig := &TLSConfig{
		InsecureSkipVerify: false, // Secure by default
	}

	client := NewClientBuilder().
		WithBaseURL(server.URL).
		WithTLS(tlsConfig).
		Build()

	resp, err := client.Get("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestNewHTTPClientWithConfig tests HTTPClient creation with Config
func TestNewHTTPClientWithConfig(t *testing.T) {
	config := Config{
		Timeout: 10 * time.Second,
		TLS: &TLSConfig{
			InsecureSkipVerify: false,
		},
	}

	httpClient := NewHTTPClient(config)

	if httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", httpClient.Timeout)
	}

	// Verify transport has TLS config
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Error("expected TLSClientConfig to be set when TLS is configured")
	} else if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false")
	}
}

// TestNewHTTPClientWithoutTLS tests HTTPClient creation without TLS
func TestNewHTTPClientWithoutTLS(t *testing.T) {
	config := Config{
		Timeout: 10 * time.Second,
		TLS:     nil, // No TLS config
	}

	httpClient := NewHTTPClient(config)

	if httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", httpClient.Timeout)
	}

	// Verify transport doesn't have TLS config
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected http.Transport")
	}

	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false when TLS is not configured")
	}
}

// TestNewHTTPClientWithInsecureTLS tests HTTPClient creation with insecure TLS
func TestNewHTTPClientWithInsecureTLS(t *testing.T) {
	config := Config{
		Timeout: 5 * time.Second,
		TLS: &TLSConfig{
			InsecureSkipVerify: true, // Development only
		},
	}

	httpClient := NewHTTPClient(config)

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected http.Transport")
	}

	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

// TestClientBuilderFullIntegration tests a complete flow with builder, OAuth2, and TLS config
func TestClientBuilderFullIntegration(t *testing.T) {
	clientID := "integration-test-client"
	clientSecret := "integration-test-secret"
	expectedToken := "integration-test-token"

	// Mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"access_token": "%s",
			"token_type": "Bearer",
			"expires_in": 3600
		}`, expectedToken)
	}))
	defer tokenServer.Close()

	// Mock API server
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/data" {
			auth := r.Header.Get("Authorization")
			if auth == "Bearer "+expectedToken {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data": "test"}`))
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer apiServer.Close()

	// Create OAuth2 authenticator
	oauth2Auth := NewOAuth2Authenticator(
		clientID,
		clientSecret,
		tokenServer.URL,
		[]string{"read", "write"},
	)

	// Build client with fluent API
	client := NewClientBuilder().
		WithBaseURL(apiServer.URL).
		WithTimeout(10 * time.Second).
		WithTLS(&TLSConfig{InsecureSkipVerify: false}).
		WithAuthenticator(oauth2Auth).
		Build()

	// Make request
	resp, err := client.Get("/api/data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading body: %v", err)
	}

	if string(body) != `{"data": "test"}` {
		t.Errorf("expected response body %q, got %q", `{"data": "test"}`, string(body))
	}
}

// TestClientBuilderExplicitTimeout verifies timeout is explicitly configured via WithTimeout.
func TestClientBuilderExplicitTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Callers should explicitly select timeout behavior.
	client := NewClientBuilder().
		WithBaseURL(server.URL).
		WithTimeout(5 * time.Second).
		Build()

	if client.httpClient.Timeout != 5*time.Second {
		t.Fatalf("expected timeout 5s, got %v", client.httpClient.Timeout)
	}

	resp, err := client.Get("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestClientBuilderMultipleAuthenticators tests builder with different authenticators
func TestClientBuilderMultipleAuthenticators(t *testing.T) {
	testCases := []struct {
		name          string
		authenticator Authenticator
		headerName    string
		headerValue   string
		expectedAuth  string
	}{
		{
			name:          "APIKey",
			authenticator: NewAPIKeyAuthenticator("secret-key", "X-API-Key"),
			headerName:    "X-API-Key",
			headerValue:   "secret-key",
			expectedAuth:  "secret-key",
		},
		{
			name:          "APIKeyDefault",
			authenticator: NewAPIKeyAuthenticator("another-key", ""),
			headerName:    "X-API-Key",
			headerValue:   "another-key",
			expectedAuth:  "another-key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get(tc.headerName)
				if auth != tc.expectedAuth {
					t.Errorf("expected header %q to be %q, got %q", tc.headerName, tc.expectedAuth, auth)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := NewClientBuilder().
				WithBaseURL(server.URL).
				WithAuthenticator(tc.authenticator).
				Build()

			resp, err := client.Get("/protected")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status OK, got %v", resp.Status)
			}
		})
	}
}

// TestBuilderConstruction validates the canonical builder construction path.
func TestBuilderConstruction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientBuilder().
		WithBaseURL(server.URL).
		WithTimeout(5 * time.Second).
		Build()

	resp, err := client.Get("/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestConfigURLResolution tests URL resolution with base URL
func TestConfigURLResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users/123" {
			t.Errorf("expected path /api/v1/users/123, got %v", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientBuilder().
		WithBaseURL(server.URL + "/api/v1").
		Build()

	resp, err := client.Get("users/123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", resp.Status)
	}
}

// TestClientBuilderPost tests POST requests with the builder pattern
func TestClientBuilderPost(t *testing.T) {
	expectedBody := "test data"
	expectedContentType := "application/json"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %v", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != expectedContentType {
			t.Errorf("expected Content-Type %q, got %q", expectedContentType, ct)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != expectedBody {
			t.Errorf("expected body %q, got %q", expectedBody, string(body))
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewClientBuilder().
		WithBaseURL(server.URL).
		Build()

	resp, err := client.Post("/data", expectedContentType, []byte(expectedBody))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status Created, got %v", resp.Status)
	}
}

// TestTLSConfigTransport verifies TLS transport is properly configured
func TestTLSConfigTransport(t *testing.T) {
	testCases := []struct {
		name                string
		tlsConfig           *TLSConfig
		expectedInsecure    bool
		shouldHaveTLSConfig bool
	}{
		{
			name:                "NoTLS",
			tlsConfig:           nil,
			expectedInsecure:    false,
			shouldHaveTLSConfig: false,
		},
		{
			name:                "SecureTLS",
			tlsConfig:           &TLSConfig{InsecureSkipVerify: false},
			expectedInsecure:    false,
			shouldHaveTLSConfig: true,
		},
		{
			name:                "InsecureTLS",
			tlsConfig:           &TLSConfig{InsecureSkipVerify: true},
			expectedInsecure:    true,
			shouldHaveTLSConfig: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				Timeout: 5 * time.Second,
				TLS:     tc.tlsConfig,
			}

			httpClient := NewHTTPClient(config)
			transport, ok := httpClient.Transport.(*http.Transport)
			if !ok {
				t.Fatal("expected *http.Transport")
			}

			if !tc.shouldHaveTLSConfig && transport.TLSClientConfig != nil {
				if transport.TLSClientConfig.InsecureSkipVerify {
					t.Error("expected InsecureSkipVerify to be false when TLS config is not provided")
				}
			}

			if tc.shouldHaveTLSConfig {
				if transport.TLSClientConfig == nil {
					t.Fatal("expected TLSClientConfig to be set")
				}
				if transport.TLSClientConfig.InsecureSkipVerify != tc.expectedInsecure {
					t.Errorf("expected InsecureSkipVerify %v, got %v",
						tc.expectedInsecure,
						transport.TLSClientConfig.InsecureSkipVerify)
				}
			}
		})
	}
}

func TestClientBuilderWithSharedTransport(t *testing.T) {
	sharedTransport := &http.Transport{}

	clientA := NewClientBuilder().
		WithTimeout(5 * time.Second).
		WithTransport(sharedTransport).
		Build()

	clientB := NewClientBuilder().
		WithTimeout(10 * time.Second).
		WithTransport(sharedTransport).
		Build()

	transportA, ok := clientA.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected clientA transport to be *http.Transport")
	}

	transportB, ok := clientB.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected clientB transport to be *http.Transport")
	}

	if transportA != sharedTransport {
		t.Fatal("expected clientA to use the shared transport instance")
	}

	if transportB != sharedTransport {
		t.Fatal("expected clientB to use the shared transport instance")
	}
}

func TestClientBuilderWithHTTPClientReuse(t *testing.T) {
	sharedClient := &http.Client{
		Timeout:   42 * time.Second,
		Transport: &http.Transport{},
	}

	client := NewClientBuilder().
		WithTimeout(1 * time.Second).
		WithTLS(&TLSConfig{InsecureSkipVerify: true}).
		WithHTTPClient(sharedClient).
		Build()

	if client.httpClient != sharedClient {
		t.Fatal("expected builder to use the provided HTTP client instance")
	}

	if client.httpClient.Timeout != 42*time.Second {
		t.Fatalf("expected provided client timeout to be preserved, got %v", client.httpClient.Timeout)
	}
}

func TestOAuth2TokenFetchUsesClientTLSConfig(t *testing.T) {
	expectedToken := "tls-test-token"

	// TLS token server — has a self-signed cert that would normally fail verification
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%s", "token_type": "Bearer", "expires_in": 3600}`, expectedToken)
	}))
	defer tokenServer.Close()

	// Plain API server — TLS is only relevant for the token fetch
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expectedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	oauth2Auth := NewOAuth2Authenticator(
		"client-id",
		"client-secret",
		tokenServer.URL+"/token",
		nil,
	)

	// InsecureSkipVerify: true — required for the self-signed cert on tokenServer
	client := NewClientBuilder().
		WithBaseURL(apiServer.URL).
		WithTimeout(5 * time.Second).
		WithTLS(&TLSConfig{InsecureSkipVerify: true}).
		WithAuthenticator(oauth2Auth).
		Build()

	resp, err := client.Get("/")
	if err != nil {
		t.Fatalf("unexpected error (token fetch likely failed TLS verification): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %v", resp.Status)
	}
}

func TestOAuth2TokenFetchFailsWithoutInsecureSkipVerify(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "token", "token_type": "Bearer", "expires_in": 3600}`)
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	oauth2Auth := NewOAuth2Authenticator("id", "secret", tokenServer.URL+"/token", nil)

	// No InsecureSkipVerify — token fetch should fail certificate verification
	client := NewClientBuilder().
		WithBaseURL(apiServer.URL).
		WithTimeout(5 * time.Second).
		WithAuthenticator(oauth2Auth).
		Build()

	_, err := client.Get("/")
	if err == nil {
		t.Fatal("expected TLS certificate verification error, got nil")
	}
}
