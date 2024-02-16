package mockoidc_test

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
)

type mockCustomerTestUserInfo struct {
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

type mockCustomeTestUserClaims struct {
	*mockoidc.IDTokenClaims
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone_number,omitempty"`
	PhoneVerified     bool     `json:"phone_verified,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

type CustomTestUser struct {
	mockoidc.MockUser
	PhoneVerified bool
}

func (ctu *CustomTestUser) scopedClone(scopes []string) *CustomTestUser {
	clone := &CustomTestUser{
		MockUser: mockoidc.MockUser{
			Subject: ctu.Subject,
		},
	}
	for _, scope := range scopes {
		switch scope {
		case "profile":
			clone.PreferredUsername = ctu.PreferredUsername
			clone.Address = ctu.Address
			clone.Phone = ctu.Phone
			clone.PhoneVerified = ctu.PhoneVerified
		case "email":
			clone.Email = ctu.Email
			clone.EmailVerified = ctu.EmailVerified
		case "groups":
			clone.Groups = append(make([]string, 0, len(ctu.Groups)), ctu.Groups...)
		}
	}
	return clone
}

func (ctu *CustomTestUser) ID() string {
	return ctu.Subject
}

func (ctu *CustomTestUser) Userinfo(scope []string) ([]byte, error) {
	user := ctu.scopedClone(scope)
	info := &mockCustomerTestUserInfo{
		Email: user.Email,
		PreferredUsername: user.PreferredUsername,
		Phone: user.Phone,
		Address: user.Address,
		Groups: user.Groups,
	}
	return json.Marshal(info)
}

func (ctu *CustomTestUser) Claim(scope []string, claims *mockoidc.IDTokenClaims) (jwt.Claims, error) {
	user := ctu.scopedClone(scope)
	return &mockCustomeTestUserClaims{
		IDTokenClaims: claims,
		Email: user.Email,
		EmailVerified: user.EmailVerified,
		PreferredUsername: user.PreferredUsername,
		Phone: user.Phone,
		PhoneVerified: user.PhoneVerified,
		Address: user.Address,
		Groups: user.Groups,
	}, nil
}
