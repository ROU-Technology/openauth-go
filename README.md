# OpenAuth Go SDK

Go server-side SDK for [OpenAuth](https://github.com/openauthjs/openauth), providing token verification and management capabilities for OpenAuth-issued tokens.

## Features

- 🔑 Verify OpenAuth-issued JWT tokens
- 📦 Efficient caching of JWKS and issuer metadata
- 🔄 Automatic token refresh support
- 🔒 Thread-safe implementation

## Installation

```bash
go get github.com/ROU-Technology/openauth-go
```

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "github.com/ROU-Technology/openauth-go"
)

func main() {
    // Initialize the client with your OpenAuth issuer URL
    client := openauth.NewClient("your-client-id", "https://your-openauth-server.com")

    // Define subject validation schema
    subjects := openauth.SubjectSchema{
        "user": func(props interface{}) error {
            // Type assert to map
            properties, ok := props.(map[string]interface{})
            if !ok {
                return fmt.Errorf("expected map[string]interface{}, got %T", props)
            }

            // Check if email exists
            email, ok := properties["email"].(string)
            if !ok {
                return fmt.Errorf("email is required and must be a string")
            }

            // Validate email format
            emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
            if !emailRegex.MatchString(email) {
                return fmt.Errorf("invalid email format")
            }

            return nil
        },
    }

    // Verify an OpenAuth-issued access token
    subject, err := client.Verify(subjects, accessToken, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Access the validated user properties
    properties := subject.Properties.(map[string]interface{})
    email := properties["email"].(string)
    fmt.Printf("Verified user with email: %s\n", email)
}
```

### HTTP Server Example

Here's an example of implementing a token verification server:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "regexp"
    "strings"

    "github.com/ROU-Technology/openauth-go"
)

var client *openauth.Client
var subjects openauth.SubjectSchema

func init() {
    // Initialize the OpenAuth client
    client = openauth.NewClient("my-client", "https://auth.myserver.com")

    // Define subject validation schema
    subjects = openauth.SubjectSchema{
        "user": func(props interface{}) error {
            properties, ok := props.(map[string]interface{})
            if !ok {
                return fmt.Errorf("expected map[string]interface{}, got %T", props)
            }

            email, ok := properties["email"].(string)
            if !ok {
                return fmt.Errorf("email is required and must be a string")
            }

            emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
            if !emailRegex.MatchString(email) {
                return fmt.Errorf("invalid email format")
            }

            return nil
        },
    }
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Get token from Authorization header
    authHeader := r.Header.Get("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
        return
    }
    token := strings.TrimPrefix(authHeader, "Bearer ")

    // Get refresh token if present
    var options *openauth.VerifyOptions
    if refreshToken := r.Header.Get("X-Refresh-Token"); refreshToken != "" {
        options = &openauth.VerifyOptions{
            RefreshToken: refreshToken,
        }
    }

    // Verify the token
    subject, err := client.Verify(subjects, token, options)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Return the verified subject
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(subject)
}

func main() {
    http.HandleFunc("/verify", verifyHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Using the HTTP Server

```bash
# Verify a token
curl -X POST http://localhost:8080/verify \
  -H "Authorization: Bearer your_access_token"

# Verify with refresh token
curl -X POST http://localhost:8080/verify \
  -H "Authorization: Bearer your_access_token" \
  -H "X-Refresh-Token: your_refresh_token"
```

Example response:

```json
{
  "type": "user",
  "properties": {
    "email": "user@example.com"
  },
  "tokens": {
    "access": "new_access_token",
    "refresh": "new_refresh_token"
  }
}
```

- Check the examples folder for more examples and usage scenarios. [Full Example](https://github.com/ROU-Technology/openauth-go/tree/main/example)

## Features in Detail

### JWKS Caching

The SDK automatically caches the OpenAuth server's JWKS (JSON Web Key Set) to minimize HTTP requests. The cache is thread-safe and uses `sync.Map` for efficient concurrent access.

### Issuer Metadata Caching

OpenAuth server configuration is cached to reduce latency and improve performance.

### Token Verification

Tokens are verified locally using the JWKS from your OpenAuth server, checking:

- Token signature
- Token expiration
- Issuer claim
- Token mode ("access")
- Custom subject validation

## Related Projects

- [OpenAuth](https://github.com/openauthjs/openauth) - The core OpenAuth server implementation
- [OpenAuth JS SDK](https://github.com/openauthjs/openauth) - JavaScript SDK for OpenAuth

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
