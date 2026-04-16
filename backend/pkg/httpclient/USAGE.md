# HTTP Client Package Usage Guide

The `httpclient` package provides a generic, composable HTTP client builder for creating HTTP clients with optional authentication and TLS configuration.

## Core Types

### `Config`
Generic configuration for HTTP clients:
```go
type Config struct {
    Timeout time.Duration
    TLS     *TLSConfig
}
```

### `TLSConfig`
Isolated TLS configuration:
```go
type TLSConfig struct {
    InsecureSkipVerify bool // Development only
}
```

### `ClientBuilder`
Fluent API for building clients:
```go
client := NewClientBuilder().
    WithBaseURL("https://api.example.com").
    WithTimeout(10 * time.Second).
    WithTLS(&TLSConfig{InsecureSkipVerify: true}).
    WithAuthenticator(oauth2Auth).
    Build()
```

Timeout behavior:
- `ClientBuilder` defaults to `Timeout: 0` (no request timeout).
- Use `WithTimeout(...)` explicitly for production workloads.

## Usage Examples

### Basic Client with OAuth2
```go
oauth2Client := httpclient.NewOAuth2Authenticator(
    "client-id",
    "client-secret",
    "https://auth.example.com/token",
    []string{"scope1", "scope2"},
)

client := httpclient.NewClientBuilder().
    WithBaseURL("https://api.example.com").
    WithTimeout(10 * time.Second).
    WithAuthenticator(oauth2Client).
    Build()

resp, err := client.Get("/users")
```

### Client with API Key Authentication
```go
apiKeyAuth := httpclient.NewAPIKeyAuthenticator("my-api-key", "X-API-Key")

client := httpclient.NewClientBuilder().
    WithBaseURL("https://api.example.com").
    WithAuthenticator(apiKeyAuth).
    Build()
```

### Development Client with Insecure TLS
```go
client := httpclient.NewClientBuilder().
    WithBaseURL("https://localhost:8080").
    WithTLS(&httpclient.TLSConfig{InsecureSkipVerify: true}).
    WithAuthenticator(oauth2Client).
    Build()
```

## Creating Custom Authenticators

Implement the `Authenticator` interface:
```go
type Authenticator interface {
    Authenticate(req *http.Request) error
}

type CustomAuth struct {
    token string
}

func (ca *CustomAuth) Authenticate(req *http.Request) error {
    req.Header.Set("Authorization", "Bearer " + ca.token)
    return nil
}
```

## Key Features

✅ **Generic** - Works with any authenticator  
✅ **Composable** - Builder pattern for flexible configuration  
✅ **Separated Concerns** - TLS, auth, and HTTP config are independent  
✅ **Clear Responsibility Boundaries** - HTTP client/transport manages connection pooling; OAuth2 authenticator injects access tokens per request  
✅ **Stable API Surface** - Keep common flows simple and use `Do(req)` for custom methods/headers  
✅ **Type-Safe** - No string-based configuration  
