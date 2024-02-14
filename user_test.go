package mockoidc_test

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
)

func TestMockUser_Userinfo(t *testing.T) {
	testUser := mockoidc.DefaultUser()
	testCases := map[string]struct {
		Scope          []string
		ExpectedEmail  string
		ExpectedPhone  string
		ExpectedGroups []string
	}{
		"all scopes": {
			Scope:          []string{"openid", "email", "profile", "groups"},
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: testUser.Groups,
		},
		"missing groups scope": {
			Scope:          []string{"openid", "email", "profile"},
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: nil,
		},
		"missing profile scope": {
			Scope:          []string{"openid", "email", "groups"},
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  "",
			ExpectedGroups: testUser.Groups,
		},
		"missing email scope": {
			Scope:          []string{"openid", "profile", "groups"},
			ExpectedEmail:  "",
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: testUser.Groups,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			payload, err := testUser.Userinfo(tc.Scope)
			assert.NoError(t, err)

			data := make(map[string]interface{})
			err = json.Unmarshal(payload, &data)
			assert.NoError(t, err)

			if tc.ExpectedEmail == "" {
				assert.Nil(t, data["email"])
			} else {
				assert.Equal(t, tc.ExpectedEmail, data["email"])
			}

			if tc.ExpectedPhone == "" {
				assert.Nil(t, data["phone_number"])
			} else {
				assert.Equal(t, tc.ExpectedPhone, data["phone_number"])
			}

			var groups []string
			if data["groups"] != nil {
				for _, group := range data["groups"].([]interface{}) {
					groups = append(groups, group.(string))
				}
			}
			assert.Equal(t, tc.ExpectedGroups, groups)
		})
	}
}

func TestMockUser_Claims(t *testing.T) {
	keypair, err := mockoidc.RandomKeypair(1024)
	assert.NoError(t, err)

	testUser := mockoidc.DefaultUser()
	testCases := map[string]struct {
		Scope          []string
		Nonce          string
		ExpectedEmail  string
		ExpectedPhone  string
		ExpectedGroups []string
	}{
		"all scopes": {
			Scope:          []string{"openid", "email", "profile", "groups"},
			Nonce:          "1234987",
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: testUser.Groups,
		},
		"missing groups scope": {
			Scope:          []string{"openid", "email", "profile"},
			Nonce:          "3948y2tiugiu",
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: nil,
		},
		"missing profile scope": {
			Scope:          []string{"openid", "email", "groups"},
			Nonce:          "",
			ExpectedEmail:  testUser.Email,
			ExpectedPhone:  "",
			ExpectedGroups: testUser.Groups,
		},
		"missing email scope": {
			Scope:          []string{"openid", "profile", "groups"},
			Nonce:          "",
			ExpectedEmail:  "",
			ExpectedPhone:  testUser.Phone,
			ExpectedGroups: testUser.Groups,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			base := &mockoidc.IDTokenClaims{
				Nonce: tc.Nonce,
			}

			claims, err := testUser.Claims(tc.Scope, base)
			assert.NoError(t, err)

			tokenStr, err := keypair.SignJWT(claims)
			assert.NoError(t, err)

			token, err := keypair.VerifyJWT(tokenStr, mockoidc.NowFunc)
			assert.NoError(t, err)
			assert.True(t, token.Valid)

			data, ok := token.Claims.(jwt.MapClaims)
			assert.True(t, ok)
			assert.NotNil(t, claims)

			if tc.Nonce == "" {
				assert.Nil(t, data["nonce"])
			} else {
				assert.Equal(t, tc.Nonce, data["nonce"])
			}

			if tc.ExpectedEmail == "" {
				assert.Nil(t, data["email"])
			} else {
				assert.Equal(t, tc.ExpectedEmail, data["email"])
			}

			if tc.ExpectedPhone == "" {
				assert.Nil(t, data["phone_number"])
			} else {
				assert.Equal(t, tc.ExpectedPhone, data["phone_number"])
			}

			var groups []string
			if data["groups"] != nil {
				for _, group := range data["groups"].([]interface{}) {
					groups = append(groups, group.(string))
				}
			}
			assert.Equal(t, tc.ExpectedGroups, groups)
		})
	}
}
