package amazoncognitoidentity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWTToken basic wrapper
type JWTToken struct {
	rawToken   string
	payload    map[string]interface{}
	expiration int
	iat        int
}

// NewJWTToken creates a token object from a raw (text) token
func NewJWTToken(token string) (*JWTToken, error) {
	payload := strings.Split(token, ".")[1]
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT token: %v", err) // TODO: create an error type
	}
	data := map[string]interface{}{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return nil, fmt.Errorf("failed to create JWT token: %v", err)
	}

	// Parse and validate 'exp'
	expStr, ok := data["exp"]
	if !ok {
		return nil, fmt.Errorf("failed to create JWT token: no 'exp' member in the payload")
	}
	exp, ok := expStr.(int)
	if !ok {
		return nil, fmt.Errorf("failed to create JWT token: 'exp' member is not an integer")
	}

	// Parse and validate 'iat'
	iatStr, ok := data["iat"]
	if !ok {
		return nil, fmt.Errorf("failed to create JWT token: no 'iat' member in the payload")
	}
	iat, ok := iatStr.(int)
	if !ok {
		return nil, fmt.Errorf("failed to create JWT token: 'iat' member is not an integer")
	}

	return &JWTToken{token, data, exp, iat}, nil
}

// Raw token
func (token *JWTToken) Raw() string {
	return token.rawToken
}

// Expiration time of the token
func (token *JWTToken) Expiration() int {
	return token.expiration
}

// IAT (Issued At) time of the token
func (token *JWTToken) IAT() int {
	return token.iat
}
