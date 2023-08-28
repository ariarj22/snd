package rest

import "github.com/kubuskotak/king/pkg/entity"

// ListDocumentsRequest Get all documents request.
type ListDocumentsRequest struct {
	entity.Filter     `json:"filter"`
	entity.Pagination `json:"pagination"`
}

// ListDocumentsResponse Get all documents response.
type ListDocumentsResponse struct {
	Documents []map[string]interface{}
}

// AddDocumentRequest Store document request.
type AddDocumentRequest map[string]interface{}

// AddDocumentResponse Store document response.
type AddDocumentResponse map[string]interface{}
