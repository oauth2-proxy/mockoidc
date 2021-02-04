package mockoidc

// User represents a mock user that the server will grant Oauth tokens for.
// Calls to the `authorization_endpoint` will pop any mock Users added to the
// `UserQueue`. Otherwise `DefaultUser()` is returned.
type User struct {
	ID                string
	Email             string `json:"email,omitempty"`
	EmailVerified     bool
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Phone             string   `json:"phone,omitempty"`
	Address           string   `json:"address,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// DefaultUser returns a default User that is set in `authorization_endpoint`
// if the UserQueue is empty.
func DefaultUser() *User {
	return &User{
		ID:                "1234567890",
		Email:             "jane.doe@example.com",
		PreferredUsername: "jane.doe",
		Phone:             "555-987-6543",
		Address:           "123 Main Street",
		Groups:            []string{"engineering", "design"},
		EmailVerified:     true,
	}
}

func (u *User) populateClaims(scopes []string, claims *idTokenClaims) {
	user := u.scopedClone(scopes)

	claims.PreferredUsername = user.PreferredUsername
	claims.Address = user.Address
	claims.Phone = user.Phone
	claims.Email = user.Email
	claims.EmailVerified = user.EmailVerified
	claims.Groups = user.Groups
}

func (u *User) scopedClone(scopes []string) *User {
	clone := &User{
		ID: u.ID,
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
