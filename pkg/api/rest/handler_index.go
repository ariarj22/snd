package rest

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"entgo.io/ent/dialect"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/jinzhu/copier"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	pkgRest "github.com/kubuskotak/asgard/rest"
	pkgTracer "github.com/kubuskotak/asgard/tracer"
	"github.com/kubuskotak/king/pkg/adapters"
	"github.com/kubuskotak/king/pkg/entity"
	"github.com/kubuskotak/king/pkg/infrastructure"
	"github.com/kubuskotak/king/pkg/persist/crud"
	"github.com/kubuskotak/king/pkg/persist/crud/ent"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/index"
)

// IndexOption is a struct holding the handler options.
type IndexOption func(index *Index)

// Index handler instance data.
type Index struct {
	*crud.Database
	*mongo.Client
}

// WithIndexDatabase option function to assign on Index.
func WithIndexDatabase(adapter *adapters.CrudPostgres) IndexOption {
	return func(h *Index) {
		h.Database = crud.Driver(crud.WithDriver(adapter.Client, dialect.Postgres))
	}
}

// WithIndexMongoDB option function to assign on Index.
func WithIndexMongoDB(adapter *adapters.CrudMongoDB) IndexOption {
	return func(h *Index) {
		h.Client = adapter.Client
	}
}

var SelectedIndexID int

// NewIndex creates a new index handler instance.
//
//	var indexHandler = rest.NewIndex()
//
//	You can pass optional configuration options by passing a Config struct:
//
//	var adaptor = &adapters.Adapter{}
//	var indexHandler = rest.NewIndex(rest.WithIndexAdapter(adaptor))
func NewIndex(opts ...IndexOption) *Index {
	// Create a new handler.
	var handler = &Index{}

	// Assign handler options.
	for o := range opts {
		var opt = opts[o]
		opt(handler)
	}

	// Return handler.
	return handler
}

// Register is endpoint group for handler.
func (h *Index) Register(router chi.Router) {
	router.Route("/apps/indexes", func(r chi.Router) {
		r.Get("/", pkgRest.HandlerAdapter[ListIndexesRequest](h.ListIndexes).JSON)
		r.Post("/", pkgRest.HandlerAdapter[AddIndexRequest](h.AddIndex).JSON)
		r.Route("/{id:[0-9A-Za-z-]+}", func(r chi.Router) {
			r.Get("/", pkgRest.HandlerAdapter[GetIndexRequest](h.GetIndex).JSON)
			r.Put("/", pkgRest.HandlerAdapter[AddIndexRequest](h.AddIndex).JSON)
			r.Delete("/", pkgRest.HandlerAdapter[DeleteIndexRequest](h.DeleteIndex).JSON)
		})
	})
}

// ListIndexes [GET /] indexes endpoint func.
func (h *Index) ListIndexes(w http.ResponseWriter, r *http.Request) (resp ListIndexesResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "ListIndexes")
		request          ListIndexesRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[ListIndexesRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind ListIndexes")
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

	// if err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	// indexes, err = query.
	// 	Limit(request.Limit).
	// 	Offset(offset).
	// 	Order(ent.Desc(index.FieldName)).
	// 	Where(index.Or(
	// 		index.NameContains(request.Query),
	// 	)).
	// 	All(ctxSpan)

	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	pipeline := bson.A{
		bson.M{"$match": bson.M{"id": userID}},
		bson.M{"$unwind": "$applications"},
		bson.M{"$match": bson.M{"applications.id": SelectedApplicationID}},
		bson.M{"$project": bson.M{
			"_id":     0,
			"indexes": "$applications.indexes",
		}},
	}
	cursor, err := collection.Aggregate(ctxSpan, pipeline)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}
	defer cursor.Close(ctxSpan)

	var result ListIndexesResponse
	if cursor.Next(ctxSpan) {
		if err := cursor.Decode(&result); err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
	} else {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("no matching document found"))
	}

	if err := cursor.Err(); err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}

	// pagination
	pkgRest.Paging(r, pkgRest.Pagination{
		Page:  request.Page,
		Limit: request.Limit,
		Total: len(result.Indexes),
	})
	// if err = copier.Copy(&rows, &indexes); err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	l.Info().Msg("ListIndexes")
	return result, nil
}

// AddIndex [POST /] index endpoint func.
func (h *Index) AddIndex(w http.ResponseWriter, r *http.Request) (resp AddIndexResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "AddIndex")
		request          AddIndexRequest
		row              *ent.Index
		artcl            entity.Index
	)
	defer span.End()

	request, err = pkgRest.GetBind[AddIndexRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind AddIndex")
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

	var client = h.Database.Index
	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	if request.ID > 0 {
		// postgres
		row, err = client.
			UpdateOneID(request.ID).
			SetName(request.Name).
			SetApplicationID(SelectedApplicationID).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
		// mongodb
		filter := bson.M{"id": int(userID), "applications.id": SelectedApplicationID}
		updatedIndex := bson.M{
			"id":   row.ID,
			"name": request.Name,
		}
		update := bson.M{
			"$set": bson.M{
				"applications.$.indexes.$[elem]": updatedIndex,
			},
		}
		arrayFilters := options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"elem.id": request.ID},
			},
		}
		_, err = collection.UpdateOne(
			ctxSpan,
			filter,
			update,
			options.Update().SetArrayFilters(arrayFilters),
		)
	} else {
		// postgres
		row, err = client.
			Create().
			SetName(request.Name).
			SetApplicationID(SelectedApplicationID).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
		// mongodb
		filter := bson.M{"id": int(userID), "applications.id": SelectedApplicationID}
		newIndex := bson.D{
			{Key: "id", Value: row.ID},
			{Key: "name", Value: request.Name},
		}
		update := bson.M{
			"$push": bson.M{
				"applications.$.indexes": newIndex,
			},
		}
		_, err = collection.UpdateOne(ctxSpan, filter, update)
	}
	if err != nil {
		// if insert mongodb error, delete record in postgres
		client.
			DeleteOneID(row.ID).
			Exec(ctxSpan)
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}

	l.Info().Interface("Index", artcl).Msg("AddIndex")
	if err = copier.Copy(&artcl, &row); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	artcl.ApplicationID = SelectedApplicationID
	return AddIndexResponse{
		Index: artcl,
	}, nil
}

// GetIndex [GET /:name] index endpoint func.
func (h *Index) GetIndex(w http.ResponseWriter, r *http.Request) (resp GetIndexResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "GetIndex")
		request          GetIndexRequest
		// row              *ent.Index
		artcl entity.Index
	)
	defer span.End()
	request, err = pkgRest.GetBind[GetIndexRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind GetIndex")
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

	// var client = h.Database.Index
	// row, err = client.
	// 	Query().
	// 	Where(index.Name(request.ID)).
	// 	First(ctxSpan)

	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	pipeline := bson.A{
		bson.M{
			"$match": bson.M{"id": int(userID)},
		},
		bson.M{
			"$unwind": "$applications",
		},
		bson.M{
			"$match": bson.M{"applications.id": SelectedApplicationID},
		},
		bson.M{
			"$unwind": "$applications.indexes",
		},
		bson.M{
			"$match": bson.M{"applications.indexes.name": request.ID},
		},
		bson.M{
			"$project": bson.M{
				"_id":  0,
				"id":   "$applications.indexes.id",
				"name": "$applications.indexes.name",
			},
		},
	}
	cursor, err := collection.Aggregate(ctxSpan, pipeline)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}
	defer cursor.Close(ctxSpan)

	if cursor.Next(ctxSpan) {
		if err := cursor.Decode(&artcl); err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
	} else {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("no matching document found"))
	}

	if err := cursor.Err(); err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}

	l.Info().Msg("GetIndexRequest")
	// if err = copier.Copy(&artcl, &row); err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	// artcl.ApplicationID = SelectedApplicationID

	// store selected index id
	SelectedIndexID = artcl.ID

	return GetIndexResponse{
		Index: artcl,
	}, nil
}

// DeleteIndex [DELETE /:name] index endpoint func.
func (h *Index) DeleteIndex(w http.ResponseWriter, r *http.Request) (resp DeleteIndexResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "DeleteIndex")
		request          DeleteIndexRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[DeleteIndexRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind DeleteIndex")
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

	var client = h.Database.Index
	database := h.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	// postgres
	row, err := client.
		Query().
		Where(index.Name(request.ID)).
		First(ctxSpan)
	err = client.
		DeleteOneID(row.ID).
		Exec(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}

	// mongodb
	filter := bson.M{"id": int(userID), "applications.id": SelectedApplicationID}
	update := bson.M{
		"$pull": bson.M{
			"applications.$.indexes": bson.M{"name": request.ID},
		},
	}
	_, err = collection.UpdateOne(ctxSpan, filter, update)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}

	l.Info().Msg("DeleteIndexRequest")
	return DeleteIndexResponse{
		Message: fmt.Sprintf("Index %s deleted", request.ID),
	}, nil
}
