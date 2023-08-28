package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

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
		// r.Get("/", pkgRest.HandlerAdapter[ListIndexesRequest](h.ListIndexes).JSON)
		r.Post("/", pkgRest.HandlerAdapter[AddDocumentRequest](h.AddDocument).JSON)
		r.Route("/{id:[0-9A-Za-z-]+}", func(r chi.Router) {
			// r.Get("/", pkgRest.HandlerAdapter[GetIndexRequest](h.GetIndex).JSON)
			r.Put("/", pkgRest.HandlerAdapter[AddIndexRequest](h.AddDocument).JSON)
			// r.Delete("/", pkgRest.HandlerAdapter[DeleteIndexRequest](h.DeleteIndex).JSON)
		})
	})
}

// AddDocument [POST /] document endpoint func.
func (h *Document) AddDocument(w http.ResponseWriter, r *http.Request) (resp map[string]interface{}, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "AddDocument")
		// request          AddDocumentRequest
	)
	defer span.End()

	// request, err = pkgRest.GetBind[AddDocumentRequest](r)
	// if err != nil {
	// 	l.Error().Err(err).Msg("Bind AddDocument")
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }
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

	var data map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	if data["_id"].(string) > "" {
		// // extract the _id field from the data
		// id, ok := data["_id"].(string)
		// if !ok {
		// 	return resp, pkgRest.ErrBadRequest(w, r, errors.New("invalid data _id format"))
		// }

		// // mongodb
		// filter := bson.M{"id": int(userID), "applications.id": SelectedApplicationID}
		// updatedIndex := bson.M{
		// 	"id":   row.ID,
		// 	"name": request.Name,
		// }
		// update := bson.M{
		// 	"$set": bson.M{
		// 		"applications.$.indexes.$[elem]": updatedIndex,
		// 	},
		// }
		// arrayFilters := options.ArrayFilters{
		// 	Filters: []interface{}{
		// 		bson.M{"elem.id": request.ID},
		// 	},
		// }
		// _, err = collection.UpdateOne(
		// 	ctxSpan,
		// 	filter,
		// 	update,
		// 	options.Update().SetArrayFilters(arrayFilters),
		// )
	} else {
		// add object id
		data["_id"] = primitive.NewObjectID()

		// mongodb
		filter := bson.M{
			"id":                      int(userID),
			"applications.id":         SelectedApplicationID,
			"applications.indexes.id": SelectedIndexID,
		}

		update := bson.M{
			"$push": bson.M{
				"applications.$.indexes.$.data": data,
			},
		}
		_, err = collection.UpdateOne(ctxSpan, filter, update)
	}

	l.Info().Interface("Document", "hai").Msg("AddDocument")

	return data, nil
}
