package mockoidc

// User defines the expected user values
type User struct {
	Email string `json: email`
	Phone string `json: phone`
	Name  string `json: name`
}

var (
	// DEFAULT_USER is a User struct that can be used wherever a user is needed
	DEFAULT_USER = User{
		Email: "user@example.com",
		Phone: "555-555-1212",
		Name:  "Jon Snow",
	}
)
