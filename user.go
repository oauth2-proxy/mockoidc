package mockoidc

// User defines the expected user values
type User struct {
	ID                string   `json: id,omitempty`
	Email             string   `json: email,omitempty`
	Phone             string   `json: phone,omitempty`
	PreferredUsername string   `json: preferred_username,omitempty`
	Address           string   `json: address,omitempty`
	Groups            []string `json: groups,omitempty`
	EmailVerified     bool     `json: email_verified,omitempty`
}

func DefaultUser() *User {
	return &User{
		ID:                "DefaultUserId",
		Email:             "defaultuser@example.com",
		Phone:             "555-555-1212",
		PreferredUsername: "Jon Snow",
		Address:           "123 Main Street, Brooklyn, NY, 11201",
		Groups:            []string{"Kings", "Northerners", "Bastards", "SnowMen"},
		EmailVerified:     true,
	}
}

// CloneForScopes returns a copy of the User with values only for the scoped information
func (u User) CloneForScopes(scopes []string) User {
	var clone User

	clone.ID = u.ID
	clone.PreferredUsername = u.PreferredUsername

	for _, scope := range scopes {
		switch scope {
		case "profile":
			clone.Address = u.Address
			clone.Phone = u.Phone
		case "email":
			clone.Email = u.Email
		case "groups":
			clone.Groups = u.Groups
		}
	}
	return clone
}

// IDClaimsForScopes returns a copy of the idtokenclaims struct with the scoped user information
func (u User) IDClaimsForScopes(scopes []string, idClaims IDTokenClaims) IDTokenClaims {
	user := u.CloneForScopes(scopes)
	idClaims.PreferredUsername = user.PreferredUsername
	idClaims.Address = user.Address
	idClaims.Phone = user.Phone
	idClaims.Email = user.Email
	idClaims.EmailVerified = user.EmailVerified
	idClaims.Groups = user.Groups
	return idClaims
}
