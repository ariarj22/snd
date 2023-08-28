package rest

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	pkgRest "github.com/kubuskotak/asgard/rest"
	pkgTracer "github.com/kubuskotak/asgard/tracer"
	"github.com/kubuskotak/king/pkg/adapters"
	"github.com/kubuskotak/king/pkg/infrastructure"
)

// DocumentOption is a struct holding the handler options.
type DocumentOption func(document *Document)

// Document handler instance data.
type Document struct {
	*mongo.Client
}

// WithDocumentMongoDB option function to assign on Document.
func WithDocumentMongoDB(adapter *adapters.CrudMongoDB) DocumentOption {
	return func(h *Document) {
		h.Client = adapter.Client
	}
}

// NewDocument creates a new document handler instance.
//
//	var documentHandler = rest.NewDocument()
//
//	You can pass optional configuration options by passing a Config struct:
//
//	var adaptor = &adapters.Adapter{}
//	var documentHandler = rest.NewDocument(rest.WithDocumentAdapter(adaptor))
func NewDocument(opts ...DocumentOption) *Document {
	// Create a new handler.
	var handler = &Document{}

	// Assign handler options.
	for o := range opts {
		var opt = opts[o]
		opt(handler)
	}

	// Return handler.
	return handler
}

// Register is endpoint group for handler.
func (h *Document) Register(router chi.Router) {
	router.Route("/apps/indexes/document", func(r chi.Router) {
		r.Get("/", pkgRest.HandlerAdapter[ListDocumentsRequest](h.ListDocuments).JSON)
		r.Post("/", pkgRest.HandlerAdapter[AddDocumentRequest](h.AddDocument).JSON)
		r.Route("/{id:[0-9A-Za-z-]+}", func(r chi.Router) {
			// r.Get("/", pkgRest.HandlerAdapter[GetDocumentRequest](h.GetDocument).JSON)
			r.Put("/", pkgRest.HandlerAdapter[AddDocumentRequest](h.AddDocument).JSON)
			r.Delete("/", pkgRest.HandlerAdapter[DeleteDocumentRequest](h.DeleteDocument).JSON)
		})
	})
}

// AddDocument [POST /] document endpoint func.
func (h *Document) AddDocument(w http.ResponseWriter, r *http.Request) (resp AddDocumentResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "AddDocument")
		request          AddDocumentRequest
	)
	defer span.End()

	request, err = pkgRest.GetBind[AddDocumentRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind AddDocument")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	// Parse and verify JWT token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("authorization token missing"))
	}

	tokenString := cookie.Value
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
		if jwtSecretKey == "" {
			return nil, fmt.Errorf("JWT_SECRET_KEY not set")
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid token"))
	}

	userID, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)

	// var data AddDocumentRequest
	// err = json.NewDecoder(r.Body).Decode(&data)
	// if err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	if request.Data["_id"] != nil {
		// mongodb
		filter := bson.M{
			"id":                            int(userID),
			"applications.id":               SelectedApplicationID,
			"applications.indexes.id":       SelectedIndexID,
			"applications.indexes.data._id": request.Data["_id"],
		}

		update := bson.M{
			"$set": bson.M{
				"applications.$[app].indexes.$[index].data.$[data]": request.Data,
			},
		}

		arrayFilters := options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"app.id": SelectedApplicationID},
				bson.M{"index.id": SelectedIndexID},
				bson.M{"data._id": request.Data["_id"]},
			},
		}

		updateOptions := options.Update().SetArrayFilters(arrayFilters)
		result, err := collection.UpdateOne(ctxSpan, filter, update, updateOptions)
		if result.ModifiedCount == 0 || err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, errors.New("error: document not found, or no selected index and/or application"))
		}
	} else {
		// mongodb
		filter := bson.M{
			"id":                      int(userID),
			"applications.id":         SelectedApplicationID,
			"applications.indexes.id": SelectedIndexID,
		}

		// add object id
		request.Data["_id"] = primitive.NewObjectID().Hex()
		update := bson.M{
			"$push": bson.M{
				"applications.$.indexes.$[index].data": request.Data,
			},
		}

		arrayFilters := options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"index.id": SelectedIndexID},
			},
		}
		updateOptions := options.Update().SetArrayFilters(arrayFilters)
		result, err := collection.UpdateOne(ctxSpan, filter, update, updateOptions)
		if result.ModifiedCount == 0 || err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, errors.New("error: document not found, or no selected index and/or application"))
		}
	}
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, err)
	}

	l.Info().Interface("Document", "").Msg("AddDocument")

	return AddDocumentResponse{
		Data: request.Data,
	}, nil
}

// ListDocuments [GET /] documents endpoint func.
func (h *Document) ListDocuments(w http.ResponseWriter, r *http.Request) (resp ListDocumentsResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "ListDocuments")
		request          ListDocumentsRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[ListDocumentsRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind ListDocuments")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	// Parse and verify JWT token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("authorization token missing"))
	}

	tokenString := cookie.Value
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
		if jwtSecretKey == "" {
			return nil, fmt.Errorf("JWT_SECRET_KEY not set")
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid token"))
	}

	userID, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	pipeline := bson.A{
		bson.M{"$match": bson.M{"id": userID}},
		bson.M{"$unwind": "$applications"},
		bson.M{"$match": bson.M{"applications.id": SelectedApplicationID}},
		bson.M{"$unwind": "$applications.indexes"},
		bson.M{"$match": bson.M{"applications.indexes.id": SelectedIndexID}},
		bson.M{"$project": bson.M{
			"_id":       0,
			"documents": "$applications.indexes.data",
		}},
	}
	cursor, err := collection.Aggregate(ctxSpan, pipeline)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, err)
	}
	defer cursor.Close(ctxSpan)

	var result ListDocumentsResponse
	if cursor.Next(ctxSpan) {
		if err := cursor.Decode(&result); err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, err)
		}
	} else {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("no matching document found"))
	}

	if err := cursor.Err(); err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, err)
	}

	// pagination
	pkgRest.Paging(r, pkgRest.Pagination{
		Page:  request.Page,
		Limit: request.Limit,
		Total: len(result.Documents),
	})

	l.Info().Msg("ListDocuments")
	return result, nil
}

// DeleteDocument [DELETE /:id] document endpoint func.
func (h *Document) DeleteDocument(w http.ResponseWriter, r *http.Request) (resp DeleteDocumentResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "DeleteDocument")
		request          DeleteDocumentRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[DeleteDocumentRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind DeleteDocument")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	// Parse and verify JWT token from cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("authorization token missing"))
	}

	tokenString := cookie.Value
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
		if jwtSecretKey == "" {
			return nil, fmt.Errorf("JWT_SECRET_KEY not set")
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid token"))
	}

	userID, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)

	// mongodb
	filter := bson.M{
		"id":                      int(userID),
		"applications.id":         SelectedApplicationID,
		"applications.indexes.id": SelectedIndexID,
	}
	update := bson.M{
		"$pull": bson.M{
			"applications.$.indexes.$[index].data": bson.M{"_id": request.ID},
		},
	}
	arrayFilters := options.ArrayFilters{
		Filters: []interface{}{
			bson.M{"index.id": SelectedIndexID},
		},
	}
	updateOptions := options.Update().SetArrayFilters(arrayFilters)
	result, err := collection.UpdateOne(ctxSpan, filter, update, updateOptions)
	if result.ModifiedCount == 0 || err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("error: document not found, or no selected index and/or application"))
	}

	l.Info().Msg("DeleteDocumentRequest")
	return DeleteDocumentResponse{
		Message: fmt.Sprintf("Document %s deleted", request.ID),
	}, nil
}
