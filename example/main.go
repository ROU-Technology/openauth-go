package main

import (
	"fmt"
	"log"

	"github.com/rou/openauth-go"
)

func main() {
	// Create a new client
	client, err := openauth.NewClient("my-client",
		openauth.WithIssuer("https://auth.myserver.com"))
	if err != nil {
		log.Fatal(err)
	}

	// Create subject validators
	subjects := openauth.SubjectSchema{
		"user": func(props interface{}) error {
			// Validate user properties here
			return nil
		},
	}

	// Example access token - replace with your actual token
	accessToken := "your-access-token"

	// Verify the access token
	subject, err := client.Verify(subjects, accessToken, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Subject type: %s, properties: %+v\n", subject.Type, subject.Properties)
}
