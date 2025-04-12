package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no auth header")
	}

	fields := strings.Fields(authHeader)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", errors.New("invalid bearer request")
	}

	if fields[1] == "" {
		return "", errors.New("empty token")
	}

	return fields[1], nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	token := hex.EncodeToString(key)

	return token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	header := headers.Get("Authorization")
	if header == "" {
		return "", errors.New("no auth header")
	}

	fields := strings.Fields(header)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "ApiKey") {
		return "", errors.New("invalid apikey request")
	}

	return fields[1], nil
}
