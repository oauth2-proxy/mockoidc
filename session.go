package mockoidc

import "github.com/dgrijalva/jwt-go"

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

// NewSession returns a pointer to a new Session struct
func NewSession(sessionID string, scopes []string, oAuthState string, oidcNonce string) (*Session, error) {
	session := Session{
		SessionID:  sessionID,
		OAuthState: oAuthState,
		OIDCNonce:  oidcNonce,
		User:       &DEFAULT_USER,
	}
	return &session, nil
}

// AccessToken returns the JWT token with the appropriate claims for an access token
func (s *Session) AccessToken(kp *Keypair) (*jwt.Token, error) {
	return nil, nil
}

// RefreshToken returns the JWT token with the appropriate claims for an access token
func (s *Session) RefreshToken(kp *Keypair) (*jwt.Token, error) {
	return nil, nil
}

// IDToken returns the JWT token with the appropriate claims for an access token
func (s *Session) IDToken(kp *Keypair) (*jwt.Token, error) {
	return nil, nil
}
