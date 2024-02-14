package mockoidc_test

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
)

var audience = jwt.ClaimStrings{"mockoidc"}

const (
	issuer     = "https://github.com/oauth2-proxy/mockoidc/"
	defaultKid = "dHXTSCyouq6DiWaQwlXtNP54-C75mw3IcoYkERfl3fQ"
)

var (
	registeredClaims = &jwt.RegisteredClaims{
		Audience:  audience,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(1) * time.Hour)),
		ID:        "0123456789abcdef",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    issuer,
		NotBefore: jwt.NewNumericDate(time.Time{}),
		Subject:   "123456789",
	}
)

func TestDefaultKeypair(t *testing.T) {
	keypair, err := mockoidc.DefaultKeypair()
	assert.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(keypair.PrivateKey)
	assert.Equal(t, mockoidc.DefaultKey, base64.RawURLEncoding.EncodeToString(keyBytes))

	kid, err := keypair.KeyID()
	assert.NoError(t, err)
	assert.Equal(t, kid, defaultKid)
}

func TestKeypair_JWKS(t *testing.T) {
	keypair, err := mockoidc.DefaultKeypair()
	assert.NoError(t, err)

	_, err = keypair.JWKS()
	assert.NoError(t, err)
}

func TestKeypair_SignJWTVerifyJWT(t *testing.T) {
	for _, size := range []int{512, 1024, 2048} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			alice, err := mockoidc.RandomKeypair(size)
			assert.NoError(t, err)
			bob, err := mockoidc.RandomKeypair(size)
			assert.NoError(t, err)

			assert.NotEqual(t, alice.PrivateKey.N, bob.PrivateKey.N)

			tokenStr, err := alice.SignJWT(registeredClaims)
			assert.NoError(t, err)

			_, err = bob.VerifyJWT(tokenStr, mockoidc.NowFunc)
			assert.Error(t, err)

			token, err := alice.VerifyJWT(tokenStr, mockoidc.NowFunc)
			assert.NoError(t, err)
			assert.True(t, token.Valid)

			claims, ok := token.Claims.(jwt.MapClaims)
			assert.True(t, ok)
			claimAudience, err := claims.GetAudience()
			assert.NoError(t, err)
			assert.Equal(t, audience, claimAudience)
			assert.Equal(t, issuer, claims["iss"])

			alice.Kid = "WRONG"
			_, err = alice.VerifyJWT(tokenStr, mockoidc.NowFunc)
			assert.Error(t, err)

			const customKid = "USER_DEFINED"
			bob.Kid = customKid
			kidTokenStr, err := bob.SignJWT(registeredClaims)
			assert.NoError(t, err)

			kidToken, err := bob.VerifyJWT(kidTokenStr, mockoidc.NowFunc)
			assert.NoError(t, err)
			assert.Equal(t, customKid, kidToken.Header["kid"])
		})
	}
}
