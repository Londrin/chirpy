package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidJWT(t *testing.T) {
	tokenSecret1 := "correctPassword123!"
	tokenSecret2 := "anotherPassword456!"
	userID1 := uuid.New()
	userID2 := uuid.New()
	token1, err := MakeJWT(userID1, tokenSecret1, time.Hour*1)
	if err != nil {
		t.Fatalf("Failed to create valid JWT in test setup: %v", err)
	}

	token2, err := MakeJWT(userID2, tokenSecret2, time.Millisecond*1) // Short expiration
	if err != nil {
		t.Fatalf("Failed to create expired JWT in test setup: %v", err)
	}
	time.Sleep(time.Millisecond * 5) // Ensure token2 expires before testing.

	tests := []struct {
		name        string
		tokensecret string
		token       string
		wantErr     bool
	}{
		{
			name:        "Correct token",
			tokensecret: tokenSecret1,
			token:       token1,
			wantErr:     false,
		},
		{
			name:        "Incorrect token",
			tokensecret: tokenSecret1,
			token:       token2,
			wantErr:     true,
		},
		{
			name:        "Token expired",
			tokensecret: tokenSecret2,
			token:       token2,
			wantErr:     true,
		},
		{
			name:        "Empty token secret",
			tokensecret: "",
			token:       token1,
			wantErr:     true,
		},
		{
			name:        "invalid token",
			tokensecret: tokenSecret1,
			token:       "invalidtoken",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ValidateJWT(tt.token, tt.tokensecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("[%s] ValidateJWT() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			if !tt.wantErr && id != userID1 {
				t.Errorf("[%s] ValidateJWT() returned incorrect userID, got %v, want %v", tt.name, id, userID1)
			}
		})
	}
}

func TestBearerToken(t *testing.T) {
	headers := http.Header{}

	// Test cases
	testCases := []struct {
		description string
		headerValue string
		expected    string
		expectError bool
	}{
		{"Valid header", "Bearer myvalidtoken123", "myvalidtoken123", false},
		{"Missing Authorization header", "", "", true},
		{"Empty Authorization header", "", "", true},
		{"No token after Bearer", "Bearer ", "", true},
		{"Wrong prefix", "Basic myvalidtoken123", "", true},
		{"Case-insensitive Bearer", "bearer myvalidtoken123", "myvalidtoken123", false},
		{"Extra fields beyond token", "Bearer myvalidtoken123 extraField", "myvalidtoken123", false},
		{"Whitespace handling", "   Bearer     myvalidtoken123   ", "myvalidtoken123", false},
	}

	// Loop through test cases
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			headers.Set("Authorization", testCase.headerValue)

			token, err := GetBearerToken(headers)

			if (err != nil) != testCase.expectError {
				t.Errorf("Unexpected error state! Got error: %v", err)
			} else if token != testCase.expected {
				t.Errorf("Unexpected token! Got: %q, Expected: %q", token, testCase.expected)
			}
		})
	}
}
