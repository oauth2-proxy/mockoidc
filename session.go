package mockoidc

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// Session stores a User and their OIDC options across requests
type Session struct {
	SessionID string
	Scopes    []string
	OIDCNonce string
	User      User
	Granted   bool
}

// SessionStore manages our Session objects
type SessionStore struct {
	Store     map[string]*Session
	CodeQueue *CodeQueue
}

// IDTokenClaims are the mandatory claims any User.Claims implementation
// should use in their jwt.Claims building.
type IDTokenClaims struct {
	Nonce string `json:"nonce,omitempty"`
	*jwt.StandardClaims
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore() *SessionStore {
	return &SessionStore{
		Store:     make(map[string]*Session),
		CodeQueue: &CodeQueue{},
	}
}

// NewSession creates a new Session for a User
func (ss *SessionStore) NewSession(scope string, nonce string, user User) (*Session, error) {
	sessionID, err := ss.CodeQueue.Pop()
	if err != nil {
		return nil, err
	}

	session := &Session{
		SessionID: sessionID,
		Scopes:    strings.Split(scope, " "),
		OIDCNonce: nonce,
		User:      user,
	}
	ss.Store[sessionID] = session

	return session, nil
}

// GetSessionByID looks up the Session
func (ss *SessionStore) GetSessionByID(id string) (*Session, error) {
	session, ok := ss.Store[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

// GetSessionByToken decodes a token and looks up a Session based on the
// session ID claim.
func (ss *SessionStore) GetSessionByToken(token *jwt.Token) (*Session, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	sessionID := claims["jti"].(string)
	return ss.GetSessionByID(sessionID)
}

// AccessToken returns the JWT token with the appropriate claims for
// an access token
func (s *Session) AccessToken(config *Config, kp *Keypair, now time.Time) (string, error) {
	claims := s.standardClaims(config, config.AccessTTL, now)
	return kp.SignJWT(claims)
}

// RefreshToken returns the JWT token with the appropriate claims for
// a refresh token
func (s *Session) RefreshToken(config *Config, kp *Keypair, now time.Time) (string, error) {
	claims := s.standardClaims(config, config.RefreshTTL, now)
	return kp.SignJWT(claims)
}

// IDToken returns the JWT token with the appropriate claims for a user
// based on the scopes set.
func (s *Session) IDToken(config *Config, kp *Keypair, now time.Time) (string, error) {
	base := &IDTokenClaims{
		StandardClaims: s.standardClaims(config, config.AccessTTL, now),
		Nonce:          s.OIDCNonce,
	}
	claims, err := s.User.Claims(s.Scopes, base)
	if err != nil {
		return "", err
	}

	return kp.SignJWT(claims)
}

func (s *Session) standardClaims(config *Config, ttl time.Duration, now time.Time) *jwt.StandardClaims {
	return &jwt.StandardClaims{
		Audience:  config.ClientID,
		ExpiresAt: now.Add(ttl).Unix(),
		Id:        s.SessionID,
		IssuedAt:  now.Unix(),
		Issuer:    config.Issuer,
		NotBefore: now.Unix(),
		Subject:   s.User.ID(),
	}
}
