package mockoidc_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/oauth2-proxy/mockoidc/v1"
	"github.com/stretchr/testify/assert"
)

const (
	audience = "mockoidc"
	issuer   = "https://github.com/oauth2-proxy/mockoidc/"
)

var (
	standardClaims = &jwt.StandardClaims{
		Audience:  audience,
		ExpiresAt: time.Now().Add(time.Duration(1) * time.Hour).Unix(),
		Id:        "0123456789abcdef",
		IssuedAt:  time.Now().Unix(),
		Issuer:    issuer,
		NotBefore: 0,
		Subject:   "123456789",
	}
)

func TestSignJWTVerifyJWT(t *testing.T) {
	for _, size := range []int{512, 1024, 2048} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			alice, err := mockoidc.RandomKeypair(size)
			assert.NoError(t, err)
			bob, err := mockoidc.RandomKeypair(size)
			assert.NoError(t, err)

			assert.NotEqual(t, alice.PrivateKey.N, bob.PrivateKey.N)

			tokenStr, err := alice.SignJWT(standardClaims)
			assert.NoError(t, err)

			_, err = bob.VerifyJWT(tokenStr)
			assert.Error(t, err)

			token, err := alice.VerifyJWT(tokenStr)
			assert.NoError(t, err)
			assert.True(t, token.Valid)

			claims, ok := token.Claims.(jwt.MapClaims)
			assert.True(t, ok)
			assert.Equal(t, audience, claims["aud"])
			assert.Equal(t, issuer, claims["iss"])

			alice.Kid = "WRONG"
			_, err = alice.VerifyJWT(tokenStr)
			assert.Error(t, err)

			const customKid = "USER_DEFINED"
			bob.Kid = customKid
			kidTokenStr, err := bob.SignJWT(standardClaims)
			assert.NoError(t, err)

			kidToken, err := bob.VerifyJWT(kidTokenStr)
			assert.NoError(t, err)
			assert.Equal(t, customKid, kidToken.Header["kid"])
		})
	}
}
