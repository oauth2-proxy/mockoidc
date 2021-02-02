package mockoidc

import (
	"errors"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Session is a struct that maintains session state across requests
type Session struct {
	SessionID  string
	Scopes     []string
	OAuthState string
	OIDCNonce  string
	User       *User
}

// SessionStore is a map of #Session structs
type SessionStore struct {
	Store map[string]*Session
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore() *SessionStore {
	var ss SessionStore
	ss.Store = make(map[string]*Session)
	return &ss
}

// NewSession returns a pointer to a new Session struct
func (ss *SessionStore) NewSession(scope string, oAuthState string, oidcNonce string, user *User) (*Session, error) {
	sessionID, err := nonce(24)
	if err != nil {
		return nil, err
	}

	session := &Session{
		SessionID:  sessionID,
		Scopes:     strings.Split(scope, " "),
		OAuthState: oAuthState,
		OIDCNonce:  oidcNonce,
		User:       user,
	}

	ss.Store[sessionID] = session

	return session, nil
}

// GetSessionByID returns the session found for the passed id, nil if no session found
func (ss *SessionStore) GetSessionByID(id string) (*Session, error) {
	session, ok := ss.Store[id]
	if ok {
		return session, nil
	} else {
		return nil, errors.New("Session not found")
	}
}

// GetSessionFromToken decodes a passed token and finds and returns the session for the encoded session id
func (ss *SessionStore) GetSessionFromToken(token *jwt.Token, now time.Time) (*Session, error) {

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("Invalid JWT")
	}

	exp := int64(claims["exp"].(float64))
	if exp < now.Unix() {
		return nil, errors.New("Expired JWT")
	}

	sessionID := claims["jti"].(string)
	return ss.GetSessionByID(sessionID)

}

// AccessToken returns the JWT token with the appropriate claims for an access token
func (s *Session) AccessToken(config *Config, kp *Keypair, now time.Time) (string, error) {

	claims := s.standardClaims(config, config.AccessTTL, now)

	return kp.SignJWT(claims)
}

// standardClaims returns a populated jwt.StandardCLaims struct
func (s *Session) standardClaims(config *Config, ttl int, now time.Time) *jwt.StandardClaims {

	return &jwt.StandardClaims{
		Audience:  config.ClientID,
		ExpiresAt: now.Unix() + int64(ttl),
		Id:        s.SessionID,
		IssuedAt:  now.Unix(),
		Issuer:    config.Issuer,
		NotBefore: now.Unix(),
		Subject:   s.User.ID,
	}
}

// RefreshToken returns the JWT token with the appropriate claims for an access token
func (s *Session) RefreshToken(config *Config, kp *Keypair, now time.Time) (string, error) {
	claims := s.standardClaims(config, config.RefreshTTL, now)

	return kp.SignJWT(claims)
}

// IDTokenClaims are the claims to be provided to jwt.Sign to create the ID token
type IDTokenClaims struct {
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Email             string   `json:"email,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	jwt.StandardClaims
}

// IDToken returns the JWT token with the appropriate claims for an access token
func (s *Session) IDToken(config *Config, kp *Keypair, now time.Time) (string, error) {

	idClaims := IDTokenClaims{
		StandardClaims: *s.standardClaims(config, config.AccessTTL, now),
	}

	idClaims = s.User.IDClaimsForScopes(s.Scopes, idClaims)

	if contains(s.Scopes, "nonce") {
		idClaims.Nonce = s.OIDCNonce
	}

	return kp.SignJWT(idClaims)
}

func contains(s []string, value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}
	return false
}
