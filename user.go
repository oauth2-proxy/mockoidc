package mockoidc

import (
	"encoding/json"

	"github.com/golang-jwt/jwt"
)

// User represents a mock user that the server will grant Oauth tokens for.
// Calls to the `authorization_endpoint` will pop any mock Users added to the
// `UserQueue`. Otherwise `DefaultUser()` is returned.
type User interface {
	// Unique ID for the User. This will be the Subject claim
	ID() string

	// Userinfo returns the Userinfo JSON representation of a User with data
	// appropriate for the passed scope []string.
	Userinfo([]string) ([]byte, error)

	// Claims returns the ID Token Claims for a User with data appropriate for
	// the passed scope []string. It builds off the passed BaseIDTokenClaims.
	Claims([]string, *IDTokenClaims) (jwt.Claims, error)
}

// MockUser is a default implementation of the User interface
type MockUser struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	Phone             string
	Address           string
	Groups            []string
}

// DefaultUser returns a default MockUser that is set in
// `authorization_endpoint` if the UserQueue is empty.
func DefaultUser() *MockUser {
	return &MockUser{
		Subject:           "1234567890",
		Email:             "jane.doe@example.com",
		PreferredUsername: "jane.doe",
		Phone:             "555-987-6543",
		Address:           "123 Main Street",
		Groups:            []string{"engineering", "design"},
		EmailVerified:     true,
	}
}

type mockUserinfo struct {
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (u *MockUser) ID() string {
	return u.Subject
}

func (u *MockUser) Userinfo(scope []string) ([]byte, error) {
	user := u.scopedClone(scope)

	info := &mockUserinfo{
		Email:             user.Email,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		Address:           user.Address,
		Groups:            user.Groups,
	}

	return json.Marshal(info)
}

type mockClaims struct {
	*IDTokenClaims
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (u *MockUser) Claims(scope []string, claims *IDTokenClaims) (jwt.Claims, error) {
	user := u.scopedClone(scope)

	return &mockClaims{
		IDTokenClaims:     claims,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		PreferredUsername: user.PreferredUsername,
		Phone:             user.Phone,
		Address:           user.Address,
		Groups:            user.Groups,
	}, nil
}

func (u *MockUser) scopedClone(scopes []string) *MockUser {
	clone := &MockUser{
		Subject: u.Subject,
	}
	for _, scope := range scopes {
		switch scope {
		case "profile":
			clone.PreferredUsername = u.PreferredUsername
			clone.Address = u.Address
			clone.Phone = u.Phone
		case "email":
			clone.Email = u.Email
			clone.EmailVerified = u.EmailVerified
		case "groups":
			clone.Groups = append(make([]string, 0, len(u.Groups)), u.Groups...)
		}
	}
	return clone
}
