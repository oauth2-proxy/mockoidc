package mockoidc

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
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
	Groups            []MockGroup
	CloudRoles        []string
	Tenant            map[string]string
	UserUuid          string
	SubType           string
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
		Groups:            []MockGroup{{Name: "engineering", UUID: "a3911826-94aa-4c00-8d99-c2a2e84e94ce"}, {Name: "design", UUID: "c1911826-94aa-4c00-8d99-c2a2e84e94cb"}},
		EmailVerified:     true,
		CloudRoles:        []string{"b199ac60-ef4a-11ee-84e9-506b8dba89b0"},
		UserUuid:          "e3911826-94aa-4c00-8d99-c2a2e84e94ca",
		SubType:           "saml",
		Tenant: map[string]string{
			"uuid": "974f10fd-ac7a-498c-93a4-e2019a4f2e76",
			"name": "xyzTenant"},
	}
}

// MockGroup is the group object
type MockGroup struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type mockUserinfo struct {
	Email             string      `json:"email,omitempty"`
	PreferredUsername string      `json:"preferred_username,omitempty"`
	Phone             string      `json:"phone_number,omitempty"`
	Address           string      `json:"address,omitempty"`
	Groups            []MockGroup `json:"groups,omitempty"`
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
	Email             string            `json:"email,omitempty"`
	EmailVerified     bool              `json:"email_verified,omitempty"`
	PreferredUsername string            `json:"preferred_username,omitempty"`
	Phone             string            `json:"phone_number,omitempty"`
	Address           string            `json:"address,omitempty"`
	Groups            []MockGroup       `json:"groups,omitempty"`
	CloudRoles        []string          `json:"cloud_roles,omitempty"`
	Tenant            map[string]string `json:"tenant,omitempty"`
	UserUuid          string            `json:"user_uuid,omitempty"`
	SubType           string            `json:"sub_type,omitempty"`
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
		CloudRoles:        user.CloudRoles,
		Tenant:            user.Tenant,
		UserUuid:          user.UserUuid,
		SubType:           user.SubType,
	}, nil
}

func (u *MockUser) scopedClone(scopes []string) *MockUser {
	clone := &MockUser{
		Subject: u.Subject,
	}
	clone.CloudRoles = u.CloudRoles
	clone.Tenant = u.Tenant
	clone.UserUuid = u.UserUuid
	clone.SubType = u.SubType
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
			clone.Groups = append(make([]MockGroup, 0, len(u.Groups)), u.Groups...)
		}
	}
	return clone
}
