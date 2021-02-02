package mockoidc

// User defines the expected user values
type User struct {
	Email string `json: email`
	Phone string `json: phone`
	Name  string `json: name`
}

const (
	DEFAULT_USER = User(
		Email: "user@example.com",
		Phone: "555-555-1212",
		Name: "Jon Snow"
	)
)
