package rest

import "github.com/kubuskotak/king/pkg/entity"

// ListApplicationsRequest Get all applications request.
type ListApplicationsRequest struct {
	entity.Filter     `json:"filter"`
	entity.Pagination `json:"pagination"`
}

// ListApplicationsResponse Get all applications response.
type ListApplicationsResponse struct {
	Applications []*entity.Application
}

// GetApplicationRequest Get an application request.
type GetApplicationRequest struct {
	entity.KeysString
}

// GetApplicationResponse Get an application response.
type GetApplicationResponse struct {
	entity.Application
}

// AddApplicationRequest Store application request.
type AddApplicationRequest struct {
	entity.Application
}

// AddApplicationResponse Store application response.
type AddApplicationResponse struct {
	entity.Application
}

// DeleteApplicationRequest Remove an application request.
type DeleteApplicationRequest struct {
	entity.KeysString
}

// DeleteApplicationResponse Remove an application response.
type DeleteApplicationResponse struct {
	Message string
}
