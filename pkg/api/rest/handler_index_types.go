package rest

import "github.com/kubuskotak/king/pkg/entity"

// ListIndexesRequest Get all indexes request.
type ListIndexesRequest struct {
	entity.Filter     `json:"filter"`
	entity.Pagination `json:"pagination"`
}

// ListIndexesResponse Get all indexes response.
type ListIndexesResponse struct {
	Indexes []*entity.Index
}

// GetIndexRequest Get an index request.
type GetIndexRequest struct {
	entity.KeysString
}

// GetIndexResponse Get an index response.
type GetIndexResponse struct {
	entity.Index
}

// AddIndexRequest Store index request.
type AddIndexRequest struct {
	entity.Index
}

// AddIndexResponse Store index response.
type AddIndexResponse struct {
	entity.Index
}

// DeleteIndexRequest Remove an index request.
type DeleteIndexRequest struct {
	entity.KeysString
}

// DeleteIndexResponse Remove an index response.
type DeleteIndexResponse struct {
	Message string
}
