package openauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// WellKnown represents the OAuth server's well-known configuration
type WellKnown struct {
	JWKsURI               string `json:"jwks_uri"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

// Client represents an OAuth client
type Client struct {
	clientID    string
	issuer      string
	httpClient  *http.Client
	issuerCache sync.Map // string -> *WellKnown
	jwksCache   sync.Map // string -> *jose.JSONWebKeySet
	wellKnown   *WellKnown
}

// getIssuer retrieves the well-known configuration for the issuer
func (c *Client) getIssuer() (*WellKnown, error) {
	// Check cache first
	if cached, ok := c.issuerCache.Load(c.issuer); ok {
		return cached.(*WellKnown), nil
	}

	// Fetch well-known configuration
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/.well-known/oauth-authorization-server", c.issuer))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known config: %w", err)
	}
	defer resp.Body.Close()

	var wellKnown WellKnown
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		return nil, fmt.Errorf("failed to decode well-known config: %w", err)
	}

	// Store in cache
	c.issuerCache.Store(c.issuer, &wellKnown)
	return &wellKnown, nil
}

// getJWKS retrieves the JSON Web Key Set from the issuer
func (c *Client) getJWKS() (*jose.JSONWebKeySet, error) {
	wellKnown, err := c.getIssuer()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer config: %w", err)
	}

	// Check cache first
	if cached, ok := c.jwksCache.Load(c.issuer); ok {
		return cached.(*jose.JSONWebKeySet), nil
	}

	// Fetch JWKS
	resp, err := c.httpClient.Get(wellKnown.JWKsURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Store in cache
	c.jwksCache.Store(c.issuer, &jwks)
	return &jwks, nil
}

// NewClient creates a new OAuth client
func NewClient(clientID string, opts ...Option) (*Client, error) {
	client := &Client{
		clientID:   clientID,
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.issuer == "" {
		client.issuer = os.Getenv("OPENAUTH_ISSUER")
		if client.issuer == "" {
			return nil, errors.New("no issuer provided")
		}
	}

	// Fetch initial well-known configuration
	if wellKnown, err := client.getIssuer(); err != nil {
		return nil, err
	} else {
		client.wellKnown = wellKnown
	}

	return client, nil
}

// Option is a function that configures the client
type Option func(*Client)

// WithIssuer sets the issuer URL
func WithIssuer(issuer string) Option {
	return func(c *Client) {
		c.issuer = issuer
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// OAuthError represents an OAuth error
type OAuthError struct {
	Code    string `json:"error"`
	Message string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// InvalidRefreshTokenError represents an error when refresh token is invalid
type InvalidRefreshTokenError struct {
	*OAuthError
}

func NewInvalidRefreshTokenError() *InvalidRefreshTokenError {
	return &InvalidRefreshTokenError{
		&OAuthError{
			Code:    "invalid_grant",
			Message: "Invalid refresh token",
		},
	}
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// VerifyOptions contains options for token verification
type VerifyOptions struct {
	RefreshToken string
}

// Subject represents a verified token subject with optional tokens
type Subject struct {
	Type       string      `json:"type"`
	Properties interface{} `json:"properties"`
	Tokens     *struct {
		Access  string `json:"access"`
		Refresh string `json:"refresh"`
	} `json:"tokens,omitempty"`
}

// SubjectValidator is a function that validates subject properties
type SubjectValidator func(properties interface{}) error

// SubjectSchema is a map of subject types to their validators
type SubjectSchema map[string]SubjectValidator

// TokenClaims represents the expected structure of the JWT claims
type TokenClaims struct {
	jwt.RegisteredClaims
	Mode       string      `json:"mode"`
	Type       string      `json:"type"`
	Properties interface{} `json:"properties"`
}

// Verify verifies an access token and returns the subject
func (c *Client) Verify(schema SubjectSchema, accessToken string, options *VerifyOptions) (*Subject, error) {
	// Get JWKS for token verification
	keySet, err := c.getJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Parse the token without verification first to get the key ID
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, &TokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get the key ID from the token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("kid header not found")
	}

	// Find the key in the key set
	keys := keySet.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("key %v not found", kid)
	}

	// Parse and verify the token with the found key
	token, err = jwt.ParseWithClaims(accessToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return keys[0].Public().Key, nil
	}, jwt.WithIssuer(c.issuer))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) && options != nil && options.RefreshToken != "" {
			// Token is expired and we have a refresh token, attempt to refresh
			issuer, err := c.getIssuer()
			if err != nil {
				return nil, fmt.Errorf("failed to get issuer: %w", err)
			}

			// Prepare the refresh token request
			data := url.Values{}
			data.Set("grant_type", "refresh_token")
			data.Set("refresh_token", options.RefreshToken)

			req, err := http.NewRequest("POST", issuer.TokenEndpoint, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, fmt.Errorf("failed to create refresh request: %w", err)
			}
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			// Make the request
			resp, err := c.httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh token: %w", err)
			}
			defer resp.Body.Close()

			var tokenResp map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				return nil, fmt.Errorf("failed to decode token response: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				return nil, NewInvalidRefreshTokenError()
			}

			// Verify the new access token
			verifiedSubject, err := c.Verify(schema, tokenResp["access_token"].(string), nil)
			if err != nil {
				return nil, fmt.Errorf("failed to verify new access token: %w", err)
			}

			// Add the new tokens to the subject
			verifiedSubject.Tokens = &struct {
				Access  string `json:"access"`
				Refresh string `json:"refresh"`
			}{

				Access:  tokenResp["access_token"].(string),
				Refresh: tokenResp["refresh_token"].(string),
			}

			return verifiedSubject, nil
		}
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	if claims.Mode != "access" {
		return nil, errors.New("invalid token mode")
	}

	validator, ok := schema[claims.Type]
	if !ok {
		return nil, fmt.Errorf("unknown subject type: %s", claims.Type)
	}

	if err := validator(claims.Properties); err != nil {
		return nil, fmt.Errorf("invalid properties: %w", err)
	}

	return &Subject{
		Type:       claims.Type,
		Properties: claims.Properties,
	}, nil
}
