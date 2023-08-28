package rest

import (
	"github.com/kubuskotak/king/pkg/entity"
)

// ListDocumentsRequest Get all documents request.
type ListDocumentsRequest struct {
	entity.Filter     `json:"filter"`
	entity.Pagination `json:"pagination"`
}

// ListDocumentsResponse Get all documents response.
type ListDocumentsResponse struct {
	Documents []map[string]interface{} `json:"documents,omitempty" bson:"documents,omitempty"`
}

// AddDocumentRequest Store document request.
type AddDocumentRequest struct {
	Data map[string]interface{} `json:"data,omitempty" bson:"data,omitempty"`
}

// AddDocumentResponse Store document response.
type AddDocumentResponse struct {
	Data map[string]interface{} `json:"data,omitempty" bson:"data,omitempty"`
}

// DeleteDocumentRequest Remove an document request.
type DeleteDocumentRequest struct {
	entity.KeysString
}

// DeleteDocumentResponse Remove an document response.
type DeleteDocumentResponse struct {
	Message string
}
