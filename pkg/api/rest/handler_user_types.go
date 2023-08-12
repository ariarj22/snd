package rest

import "github.com/kubuskotak/king/pkg/entity"

// ListUsersRequest Get all users request.
type ListUsersRequest struct {
	entity.Filter     `json:"filter"`
	entity.Pagination `json:"pagination"`
}

// ListUsersResponse Get all users response.
type ListUsersResponse struct {
	Users []*entity.User
}

// GetUserRequest Get an user request.
type GetUserRequest struct {
	entity.Keys
}

// GetUserResponse Get an user response.
type GetUserResponse struct {
	entity.User
}

// RegisterUserRequest Store user request.
type RegisterUserRequest struct {
	entity.User
}

// RegisterUserResponse Store user response.
type RegisterUserResponse struct {
	entity.User
}

// LoginUserRequest Store user request.
type LoginUserRequest struct {
	entity.User
}

// LoginUserResponse Store user response.
type LoginUserResponse struct {
	Message string
}

// DeleteUserRequest Remove an user request.
type DeleteUserRequest struct {
	entity.Keys
}

// DeleteUserResponse Remove an user response.
type DeleteUserResponse struct {
	Message string
}
