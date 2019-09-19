package amazoncognitoidentity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

const initN = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

var newPasswordRequiredChallengeUserAttributePrefix = "userAttributes."

// AuthenticationHelper removes some boilerplate code
type AuthenticationHelper struct {
	N           big.Int
	g           big.Int
	k           big.Int
	smallAValue big.Int
	largeAValue *big.Int
	infoBits    []byte
	poolName    string
	UValue      *big.Int
	UHexHash    string
}

// NewAuthenticationHelper returns a new helper
func NewAuthenticationHelper(poolName string) *AuthenticationHelper {
	var helper AuthenticationHelper

	helper.N.SetString(initN, 16)
	helper.g.SetString("2", 16)
	helper.k.SetString(hexHash("00"+helper.N.Text(16)+"0"+helper.g.Text(16)), 16)

	helper.smallAValue = helper.generateRandomSmallA()
	helper.GetLargeAValue()

	helper.infoBits = []byte("Caldera Derived Key")
	helper.poolName = poolName
	return &helper
}

func hexHash(hexStr string) string {
	b, _ := hex.DecodeString(hexStr)
	return hash(b)
}

func hash(buf []byte) string {
	h := sha256.New()
	h.Write(buf)
	hashHex := fmt.Sprintf("%x", h.Sum(nil))
	return strings.Repeat("0", 64-len(hashHex)) + hashHex
}

func (helper AuthenticationHelper) generateRandomSmallA() big.Int {
	bytesRandom := make([]byte, 128)
	rand.Read(bytesRandom)
	hexRandom := fmt.Sprintf("%x", bytesRandom)

	var randomBigInt, smallABigInt big.Int
	randomBigInt.SetString(hexRandom, 16)
	smallABigInt.Mod(&randomBigInt, &helper.N)

	return smallABigInt
}

// GetLargeAValue returns the large A value
func (helper *AuthenticationHelper) GetLargeAValue() *big.Int {
	if helper.largeAValue == nil {
		helper.largeAValue = helper.calculateA(helper.smallAValue)
	}
	return helper.largeAValue
}

func (helper AuthenticationHelper) calculateA(a big.Int) *big.Int {
	var modPow big.Int

	res := modPow.Exp(&helper.g, &a, &helper.N)
	return res
}

func (helper *AuthenticationHelper) computehkdf(ikm, salt []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)

	infoBit := append(helper.infoBits, byte(1))

	h = hmac.New(sha256.New, prk)
	h.Write(infoBit)
	return h.Sum(nil)[0:16]
}

// GetPasswordAuthenticationKey returns the password authentication key
func (helper *AuthenticationHelper) GetPasswordAuthenticationKey(username, password string, serverBValue, salt *big.Int) []byte {
	helper.UValue = helper.calculateU(helper.largeAValue, serverBValue)

	usernamePassword := helper.poolName + username + ":" + password
	usernamePasswordHash := hash([]byte(usernamePassword))

	xValue, _ := big.NewInt(0).SetString(hexHash(padHex(salt)+usernamePasswordHash), 16)
	sValue := helper.calculateS(xValue, serverBValue)
	ikm, _ := hex.DecodeString(padHex(sValue))
	saltb, _ := hex.DecodeString(padHex(helper.UValue))
	hkdf := helper.computehkdf(ikm, saltb)
	return hkdf
}

func (helper *AuthenticationHelper) calculateU(A, B *big.Int) *big.Int {
	helper.UHexHash = hexHash(padHex(A) + padHex(B))
	finalU, _ := big.NewInt(0).SetString(helper.UHexHash, 16)
	// fmt.Println("UValue", finalU.Text(16), "\n")
	return finalU
}

func padHex(val *big.Int) string {
	hashStr := val.Text(16)

	if len(hashStr)%2 == 1 {
		hashStr = "0" + hashStr
	} else if strings.Contains("89ABCDEFabcdef", string(hashStr[0])) {
		hashStr = "00" + hashStr
	}
	return hashStr
}

func (helper *AuthenticationHelper) calculateS(xValue, serverBValue *big.Int) *big.Int {
	I := func() *big.Int { return big.NewInt(0) }

	gModPowXN := I().Exp(&helper.g, xValue, &helper.N)
	intValue2 := I().Sub(serverBValue, I().Mul(&helper.k, gModPowXN))
	result := I().Exp(intValue2, I().Add(&helper.smallAValue, I().Mul(helper.UValue, xValue)), &helper.N)
	s := I().Mod(result, &helper.N)
	return s
}
