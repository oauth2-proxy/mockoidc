package mockoidc

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestNewSessionStore(t *testing.T) {
	ss := NewSessionStore()
	assert.NotNil(t, ss)
	assert.NotNil(t, ss.Store)
}

func TestNewSession(t *testing.T) {
	ss := NewSessionStore()
	scope := "openid profile"
	oAuthState := "state"
	oidcNonce := "nonce"
	user := DefaultUser()

	session, err := ss.NewSession(scope, oAuthState, oidcNonce, user)

	assert.NoError(t, err)
	assert.Equalf(t, len(session.Scopes), 2, "Incorrect scope count: %v", len(session.Scopes))
	assert.Equalf(t, len(ss.Store), 1, "Wrong number of sessions in the session store: %d", len(ss.Store))
	assert.Equalf(t, ss.Store[session.SessionID], session, "Session not stored in session store")
}

func TestAccessToken(t *testing.T) {
	session := defaultSession()
	config := defaultConfig()
	keypair, _ := RandomKeypair(2048)
	tokenString, err := session.AccessToken(&config, keypair, NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, session.SessionID, claims["jti"])
	assert.Equal(t, config.ClientID, claims["aud"])
	assert.Equal(t, config.Issuer, claims["iss"])
	assert.Equal(t, session.User.ID, claims["sub"])

}
func TestRefreshToken(t *testing.T) {
	session := defaultSession()
	config := defaultConfig()
	keypair, _ := RandomKeypair(2048)
	tokenString, err := session.RefreshToken(&config, keypair, NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, session.SessionID, claims["jti"])
	assert.Equal(t, config.ClientID, claims["aud"])
	assert.Equal(t, config.Issuer, claims["iss"])
	assert.Equal(t, session.User.ID, claims["sub"])
}

func TestIDToken(t *testing.T) {
	session := defaultSession()
	config := defaultConfig()
	keypair, _ := RandomKeypair(2048)
	tokenString, err := session.IDToken(&config, keypair, NowFunc())
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.NotNil(t, claims)

	assert.Equal(t, session.SessionID, claims["jti"])
	assert.Equal(t, config.ClientID, claims["aud"])
	assert.Equal(t, config.Issuer, claims["iss"])
	assert.Equal(t, session.User.ID, claims["sub"])

	assert.Equal(t, session.User.PreferredUsername, claims["preferred_username"])
	assert.Equal(t, session.User.Address, claims["address"])
	assert.Equal(t, session.User.Phone, claims["phone_number"])
	assert.Nil(t, claims["groups"])
}

func TestGetSessionByID(t *testing.T) {
	ss := NewSessionStore()

	scope := "openid profile"
	oAuthState := "state"
	oidcNonce := "nonce"
	user := DefaultUser()
	_, err := ss.NewSession(scope, oAuthState, oidcNonce, user)
	assert.NoError(t, err)

	scope = "openid profile email"
	oAuthState = "DifferentState"
	oidcNonce = "nonce"
	user2 := User{
		ID:                "DifferentUserId",
		Email:             "differentuser@example.com",
		Phone:             "555-555-diff",
		PreferredUsername: "Jon Diff",
		Address:           "123 Diff Street, Brooklyn, NY, 11201",
		Groups:            []string{"Kings", "Northerners", "Bastards", "Different"},
		EmailVerified:     true,
	}
	s2, err := ss.NewSession(scope, oAuthState, oidcNonce, &user2)
	assert.NoError(t, err)

	session, err := ss.GetSessionByID(s2.SessionID)
	assert.NoError(t, err)
	assert.Equal(t, session, s2)

	session, err = ss.GetSessionByID("Fake Session ID")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestGetSessionFromToken(t *testing.T) {
	ss := NewSessionStore()

	scope := "openid profile"
	oAuthState := "state"
	oidcNonce := "nonce"
	user := DefaultUser()
	_, err := ss.NewSession(scope, oAuthState, oidcNonce, user)
	assert.NoError(t, err)

	scope = "openid profile email"
	oAuthState = "DifferentState"
	oidcNonce = "nonce"
	user2 := User{
		ID:                "DifferentUserId",
		Email:             "differentuser@example.com",
		Phone:             "555-555-diff",
		PreferredUsername: "Jon Diff",
		Address:           "123 Diff Street, Brooklyn, NY, 11201",
		Groups:            []string{"Kings", "Northerners", "Bastards", "Different"},
		EmailVerified:     true,
	}
	s2, err := ss.NewSession(scope, oAuthState, oidcNonce, &user2)
	assert.NoError(t, err)

	keypair, _ := RandomKeypair(2048)
	config := defaultConfig()

	now := time.Now()
	tokenString, err := s2.AccessToken(&config, keypair, now)
	assert.NoError(t, err)

	token, err := keypair.VerifyJWT(tokenString)
	assert.NoError(t, err)

	session, err := ss.GetSessionFromToken(token, now)
	assert.NoError(t, err)
	assert.Equal(t, session, s2)

	tooLate := now.Add(time.Minute * time.Duration(11))
	session, err = ss.GetSessionFromToken(token, tooLate)
	assert.Error(t, err)
	assert.Nil(t, session)

	delete(ss.Store, s2.SessionID)
	session, err = ss.GetSessionFromToken(token, now)
	assert.Error(t, err)
	assert.Nil(t, session)

}

func defaultConfig() Config {
	return Config{
		ClientID:     "Config.ClientId",
		ClientSecret: "Config.ClientSecret",
		Issuer:       "issuer.example.com",
		AccessTTL:    600,
		RefreshTTL:   14400,
	}
}
func defaultSession() Session {
	return Session{
		SessionID:  "DefaultSessionId",
		Scopes:     []string{"profile", "openid"},
		OAuthState: "SomeOauthState",
		User:       DefaultUser(),
	}
}
