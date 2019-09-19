package amazoncognitoidentity

// AuthOptions store authentification options
type AuthOptions struct {
	UserPoolID          *string
	UserPoolWebClientID *string
	IdentityPoolID      *string
	Region              *string
	MandatorySignIn     *bool
	// CookieStorage          ICookieStorageData
	// Oauth                  OAuth
	// RefreshHandlers        object
	// Storage                ICognitoStorage
	AuthenticationFlowType *string
	IdentityPoolRegion     *string
}

// Auth store data relatives to authentification
type Auth struct {
	config   AuthOptions
	userPool *UserPool
	user     *User
}

// AuthenticationResult store authentication tokens
type AuthenticationResult struct {
	AccessToken  string
	IDToken      string `json:"idToken"`
	RefreshToken string
	ExpiresIn    int
	TokenType    string
}

// NewAuth return a new Auth object
func NewAuth(config AuthOptions) (*Auth, error) {
	var auth Auth

	auth.configure(config)
	return &auth, nil
}

func (auth *Auth) configure(config AuthOptions) {
	if config.UserPoolID != nil {
		auth.userPool = NewUserPool(*config.UserPoolID, *config.UserPoolWebClientID, nil)
	}
}

func (auth *Auth) createCognitoUser(username string) (*User, error) {
	return NewUser(&UserOptions{
		Username: &username,
		Pool:     auth.userPool,
	})
}

// SignInWithPassword to sign in with a password
func (auth *Auth) SignInWithPassword(username, password string) (AuthenticationResult, error) {
	user, _ := auth.createCognitoUser(username)
	return user.AuthenticateUser(username, password)
}
