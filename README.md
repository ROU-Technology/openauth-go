# OpenAuth Go SDK

Go server-side SDK for [OpenAuth](https://github.com/openauthjs/openauth), providing token verification and management capabilities for OpenAuth-issued tokens.

## Features

- 🔑 Verify OpenAuth-issued JWT tokens
- 📦 Efficient caching of JWKS and issuer metadata
- 🔄 Automatic token refresh support
- 🔒 Thread-safe implementation
- 🚀 High performance with minimal dependencies

## Installation

```bash
go get github.com/ROU-Technology/openauth-go
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/ROU-Technology/openauth-go"
)

func main() {
    // Initialize the client with your OpenAuth issuer URL
    client := openauth.NewClient("your-client-id", "https://your-openauth-server.com")

    // Define subject validation schema for your application's subjects
    subjects := openauth.SubjectSchema{
        "user": func(properties interface{}) error {
            // Add your validation logic for user subjects
            return nil
        },
    }

    // Verify an OpenAuth-issued access token
    subject, err := client.Verify(subjects, accessToken, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Use the verified subject
    log.Printf("Verified subject type: %s", subject.Type)
}
```

## Token Refresh

The SDK supports automatic refresh of expired OpenAuth tokens:

```go
subject, err := client.Verify(subjects, accessToken, &openauth.VerifyOptions{
    RefreshToken: refreshToken,
})
if err != nil {
    log.Fatal(err)
}

// New tokens are available in the subject
if subject.Tokens != nil {
    newAccessToken := subject.Tokens.Access
    newRefreshToken := subject.Tokens.Refresh
}
```

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
