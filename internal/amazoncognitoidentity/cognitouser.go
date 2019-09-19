package amazoncognitoidentity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ludonope/gocognito/internal/amazoncognitoidentity/datehelper"
)

// User store user's informations
type User struct {
	username string
	pool     *UserPool
	session  *string // TODO: set the right type
	client   *Client
}

// UserOptions store user options
type UserOptions struct {
	Username *string
	Pool     *UserPool
}

// AuthParameters store authentification parameters
type AuthParameters struct {
	Username string `json:"USERNAME"`
	SRPA     string `json:"SRP_A"`
}

// JSONReq store the json request
type JSONReq struct {
	AuthFlow       string
	ClientID       string `json:"ClientId"`
	AuthParameters AuthParameters
	ClientMetadata interface{}
}

type challenge struct {
	ChallengeName       string
	ChallengeParameters map[string]string
}

// JSONReqResp store the json request response to the challenge
type JSONReqResp struct {
	ChallengeName      string
	ClientID           string `json:"ClientId"`
	ChallengeResponses challengeResponses
}

type challengeResponses struct {
	Username                 string `json:"USERNAME"`
	PasswordClaimSecretBlock string `json:"PASSWORD_CLAIM_SECRET_BLOCK"`
	Timestamp                string `json:"TIMESTAMP"`
	PasswordClaimSignature   string `json:"PASSWORD_CLAIM_SIGNATURE"`
}

// NewUser returns a new user
func NewUser(data *UserOptions) (*User, error) {
	var user User

	if data == nil || data.Username == nil || data.Pool == nil {
		return nil, fmt.Errorf("username and pool information are required")
	}

	user.username = *data.Username
	user.pool = data.Pool
	user.session = nil

	user.client = data.Pool.Client

	return &user, nil
}

// setSignInUserSession
// getSignInUserSession
// getUsername
// getAuthenticationFlowType
// setAuthenticationFlowType
// initiateAuth
// authenticateUser
// authenticateUserDefaultAuth
// authenticateUserPlainUsernamePassword
// authenticateUserInternal
// completeNewPasswordChallenge
// getDeviceResponse
// confirmRegistration
// sendCustomChallengeAnswer
// sendMFACode
// changePassword
// enableMFA
// setUserMFAPreference
// disableMFA
// deleteUser
// updateAttributes
// getUserAttributes
// getMFAOptions
// getUserData
// deleteAttributes
// resendConfirmationCode
// getSession
// refreshSession
// cacheTokens
// cacheUserData
// clearCachedUser
// cacheDeviceKeyAndPassword
// getCachedDeviceKeyAndPassword
// clearCachedDeviceKeyAndPassword
// clearCachedTokens
// getCognitoUserSession
// forgotPassword
// confirmPassword
// getAttributeVerificationCode
// verifyAttribute
// getDevice
// forgetSpecificDevice
// forgetDevice
// setDeviceStatusRemembered
// setDeviceStatusNotRemembered
// listDevices
// globalSignOut
// signOut
// sendMFASelectionAnswer
// getUserContextData
// associateSoftwareToken
// verifySoftwareToken

// AuthenticateUser authenticates a user
func (user *User) AuthenticateUser(username, password string) (AuthenticationResult, error) {
	userPoolID := user.pool.GetUserPoolID()
	poolName := strings.Split(userPoolID, "_")[1]
	authenticationHelper := NewAuthenticationHelper(poolName)

	largeAValue := authenticationHelper.GetLargeAValue()
	authParameters := AuthParameters{
		Username: user.username,
		SRPA:     largeAValue.Text(16),
	}

	jsonReq := JSONReq{
		AuthFlow:       "USER_SRP_AUTH",
		ClientID:       user.pool.GetClientID(),
		AuthParameters: authParameters,
		ClientMetadata: map[string]string{},
	}

	resp := user.client.Request("InitiateAuth", jsonReq)
	var chal challenge
	json.Unmarshal(resp, &chal)

	var serverBValue, salt big.Int

	user.username = chal.ChallengeParameters["USERNAME"]
	userID := chal.ChallengeParameters["USER_ID_FOR_SRP"]
	serverBValue.SetString(chal.ChallengeParameters["SRP_B"], 16)
	salt.SetString(chal.ChallengeParameters["SALT"], 16)
	secretBlock64 := chal.ChallengeParameters["SECRET_BLOCK"]

	hkdf := authenticationHelper.GetPasswordAuthenticationKey(userID, password, &serverBValue, &salt)
	dateNow := datehelper.GetNowString()

	h := hmac.New(sha256.New, hkdf)
	secretBlock, err := base64.StdEncoding.DecodeString(secretBlock64)
	if err != nil {
		fmt.Println("invalid secretBlock", hkdf)
		panic(err)
	}
	var input, update []byte
	input = append(input, []byte(poolName+userID)...)
	input = append(input, secretBlock...)
	input = append(input, []byte(dateNow)...)
	update = input
	_, err = h.Write(update)
	if err != nil {
		fmt.Println("Failed to write update")
		panic(err)
	}
	signatureString := base64.StdEncoding.EncodeToString(h.Sum(nil))

	jsonReqResp := JSONReqResp{
		ChallengeName: chal.ChallengeName,
		ClientID:      user.pool.GetClientID(),
		ChallengeResponses: challengeResponses{
			Username:                 userID,
			PasswordClaimSecretBlock: secretBlock64,
			Timestamp:                dateNow,
			PasswordClaimSignature:   signatureString,
		},
	}

	resp = user.client.Request("RespondToAuthChallenge", jsonReqResp)
	var result struct{ AuthenticationResult AuthenticationResult }
	json.Unmarshal(resp, &result)
	return result.AuthenticationResult, nil
}
