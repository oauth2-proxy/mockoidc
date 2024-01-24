package mockoidc_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
)

var (
	dummyConfig = &mockoidc.Config{
		ClientID:     "Config.ClientId",
		ClientSecret: "Config.ClientSecret",
		Issuer:       "issuer.example.com",
		AccessTTL:    600 * time.Second,
		RefreshTTL:   14400 * time.Second,
	}
	dummySession = &mockoidc.Session{
		SessionID: "DefaultSessionId",
		Scopes:    []string{"openid", "email", "profile", "groups"},
		User:      mockoidc.DefaultUser(),
	}
)

func TestNewSessionStore(t *testing.T) {
	ss := mockoidc.NewSessionStore()
	assert.NotNil(t, ss)
	assert.NotNil(t, ss.Store)
}

func TestSessionStore_NewSession(t *testing.T) {
	ss := mockoidc.NewSessionStore()
	const (
		scope     = "openid email profile"
		oidcNonce = "nonce"
	)
	user := mockoidc.DefaultUser()

	session, err := ss.NewSession(scope, oidcNonce, user, "sum", "S256")

	assert.NoError(t, err)
	assert.Equal(t, session.Scopes, []string{"openid", "email", "profile"})
	assert.Equal(t, len(ss.Store), 1)
	assert.Equal(t, ss.Store[session.SessionID], session)
	assert.Equal(t, session.CodeChallenge, "sum")
	assert.Equal(t, session.CodeChallengeMethod, "S256")
}

func TestSession_AccessToken(t *testing.T) {
	keypair, _ := mockoidc.DefaultKeypair()
	tokenString, err := dummySession.AccessToken(dummyConfig, keypair, mockoidc.NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString, mockoidc.NowFunc)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, dummySession.SessionID, claims["jti"])
	claimAudience, err := claims.GetAudience()
	assert.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{dummyConfig.ClientID}, claimAudience)
	assert.Equal(t, dummyConfig.Issuer, claims["iss"])
	assert.Equal(t, dummySession.User.ID(), claims["sub"])
}

func TestSession_RefreshToken(t *testing.T) {
	keypair, _ := mockoidc.DefaultKeypair()
	tokenString, err := dummySession.RefreshToken(dummyConfig, keypair, mockoidc.NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString, mockoidc.NowFunc)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, dummySession.SessionID, claims["jti"])
	claimsAudience, err := claims.GetAudience()
	assert.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{dummyConfig.ClientID}, claimsAudience)
	assert.Equal(t, dummyConfig.Issuer, claims["iss"])
	assert.Equal(t, dummySession.User.ID(), claims["sub"])
}

func TestSession_IDToken(t *testing.T) {
	keypair, _ := mockoidc.DefaultKeypair()
	tokenString, err := dummySession.IDToken(dummyConfig, keypair, mockoidc.NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString, mockoidc.NowFunc)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, dummySession.SessionID, claims["jti"])
	claimsAudience, err := claims.GetAudience()
	assert.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{dummyConfig.ClientID}, claimsAudience)
	assert.Equal(t, dummyConfig.Issuer, claims["iss"])
	assert.Equal(t, dummySession.User.ID(), claims["sub"])

	u := dummySession.User.(*mockoidc.MockUser)
	assert.Equal(t, u.PreferredUsername, claims["preferred_username"])
	assert.Equal(t, u.Address, claims["address"])
	assert.Equal(t, u.Phone, claims["phone_number"])

	groups, ok := claims["groups"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, len(groups), 2)
}

func TestSessionStore_GetSessionByID(t *testing.T) {
	ss := mockoidc.NewSessionStore()

	const (
		scope     = "openid email profile"
		oidcNonce = "nonce"
	)
	user := mockoidc.DefaultUser()
	_, err := ss.NewSession(scope, oidcNonce, user, "sum", "S256")
	assert.NoError(t, err)

	user2 := &mockoidc.MockUser{
		Subject:           "DifferentUserId",
		Email:             "different.user@example.com",
		Phone:             "555-555-5555",
		PreferredUsername: "Jon Diff",
		Address:           "123 Diff Street",
		Groups:            []string{"another", "different"},
		EmailVerified:     true,
	}
	s2, err := ss.NewSession(scope, oidcNonce, user2, "", "")
	assert.NoError(t, err)

	session, err := ss.GetSessionByID(s2.SessionID)
	assert.NoError(t, err)
	assert.Equal(t, session, s2)

	session, err = ss.GetSessionByID("Fake Session ID")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestSessionStore_GetSessionFromToken(t *testing.T) {
	ss := mockoidc.NewSessionStore()

	const (
		scope     = "openid email profile"
		oidcNonce = "nonce"
	)
	user := mockoidc.DefaultUser()
	_, err := ss.NewSession(scope, oidcNonce, user, "sum", "S256")
	assert.NoError(t, err)

	user2 := &mockoidc.MockUser{
		Subject:           "DifferentUserId",
		Email:             "different.user@example.com",
		Phone:             "555-555-5555",
		PreferredUsername: "Jon Diff",
		Address:           "123 Diff Street",
		Groups:            []string{"another", "different"},
		EmailVerified:     true,
	}
	s2, err := ss.NewSession(scope, oidcNonce, user2, "sum", "S256")
	assert.NoError(t, err)

	keypair, err := mockoidc.DefaultKeypair()
	assert.NoError(t, err)

	now := time.Now()
	tokenString, err := s2.AccessToken(dummyConfig, keypair, now)
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString, mockoidc.NowFunc)
	assert.NoError(t, err)

	session, err := ss.GetSessionByToken(token)
	assert.NoError(t, err)
	assert.Equal(t, session, s2)

	delete(ss.Store, s2.SessionID)
	session, err = ss.GetSessionByToken(token)
	assert.Error(t, err)
	assert.Nil(t, session)
}
