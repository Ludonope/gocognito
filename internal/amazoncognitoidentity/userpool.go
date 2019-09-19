package amazoncognitoidentity

import "strings"

// UserPool store user pool informations
type UserPool struct {
	userPoolID string
	clientID   string
	Client     *Client
}

// NewUserPool returns a new user pool
func NewUserPool(userPoolID, clientID string, endpoint *string) *UserPool {
	userPool := UserPool{
		userPoolID: userPoolID,
		clientID:   clientID,
	}

	region := strings.Split(userPoolID, "_")[0]
	userPool.Client = NewClient(region, endpoint)
	return &userPool
}

// GetUserPoolID returns the user pool ID
func (pool UserPool) GetUserPoolID() string {
	return pool.userPoolID
}

// GetClientID returns the user pool ID
func (pool UserPool) GetClientID() string {
	return pool.clientID
}
