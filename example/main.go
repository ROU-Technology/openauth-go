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
	client = openauth.NewClient("client", "http://localhost:3000")

	// Define subject validation schema
	subjects = openauth.SubjectSchema{
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
}

type VerifyResponse struct {
	Type       string      `json:"type"`
	Properties interface{} `json:"properties"`
	Tokens     *struct {
		Access  string `json:"access"`
		Refresh string `json:"refresh"`
	} `json:"tokens,omitempty"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeError(w, "invalid_request", "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Extract the token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		writeError(w, "invalid_request", "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}
	accessToken := parts[1]

	// Get refresh token from header if present
	var options *openauth.VerifyOptions
	if refreshToken := r.Header.Get("X-Refresh-Token"); refreshToken != "" {
		options = &openauth.VerifyOptions{
			RefreshToken: refreshToken,
		}
	}

	fmt.Printf("Access token: %s\n", accessToken)
	fmt.Printf("Refresh token: %s\n", options.RefreshToken)

	// Verify the token
	subject, err := client.Verify(subjects, accessToken, options)
	if err != nil {
		writeError(w, "invalid_token", err.Error(), http.StatusUnauthorized)
		return
	}

	// Return the verified subject
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{
		Type:       subject.Type,
		Properties: subject.Properties,
		Tokens:     subject.Tokens,
	})
}

func writeError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:       code,
		Description: description,
	})
}

func main() {
	// Register routes
	http.HandleFunc("/verify", verifyHandler)

	// Start server
	port := ":8080"
	fmt.Printf("Server starting on http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
