package entity

// Application data transfer object.
type Application struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty" validate:"required"`
	ApiKey string `json:"apikey,omitempty"`
	UserID int    `json:"user_id,omitempty"`
}
