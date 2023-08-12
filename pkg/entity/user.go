package entity

// User data transfer object.
type User struct {
	ID       int    `json:"id,omitempty"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty" validate:"required,min=8"`
}
