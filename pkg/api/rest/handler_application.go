package rest

import (
	"errors"
	"fmt"
	"math/rand"
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
)

// ApplicationOption is a struct holding the handler options.
type ApplicationOption func(application *Application)

// Application handler instance data.
type Application struct {
	*crud.Database
	*mongo.Client
}

// WithApplicationDatabase option function to assign on Application
func WithApplicationDatabase(adapter *adapters.CrudPostgres) ApplicationOption {
	return func(a *Application) {
		a.Database = crud.Driver(crud.WithDriver(adapter.Client, dialect.Postgres))
	}
}

// WithApplicationMongoDB option function to assign on Application
func WithApplicationMongoDB(adapter *adapters.CrudMongoDB) ApplicationOption {
	return func(a *Application) {
		a.Client = adapter.Client
	}
}

// NewApplication creates a new application handler instance.
//
//	var applicationHandler = rest.NewApplication()
//
//	You can pass optional configuration options by passing a Config struct:
//
//	var adaptor = &adapters.Adapter{}
//	var applicationHandler = rest.NewApplication(rest.WithApplicationAdapter(adaptor))
func NewApplication(opts ...ApplicationOption) *Application {
	// Create a new handler.
	var handler = &Application{}

	// Assign handler options.
	for o := range opts {
		var opt = opts[o]
		opt(handler)
	}

	// Return handler.
	return handler
}

// Generate application id.
func generateApplicationID() string {
	const applicationIDLength = 10
	const applicationIDCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	id := make([]byte, applicationIDLength)
	for i := range id {
		id[i] = applicationIDCharset[rand.Intn(len(applicationIDCharset))]
	}
	return string(id)
}

// Generate apikey for application.
func generateAPIKey() string {
	const apiKeyLength = 32
	const apiKeyCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
	key := make([]byte, apiKeyLength)
	for i := range key {
		key[i] = apiKeyCharset[rand.Intn(len(apiKeyCharset))]
	}
	return string(key)
}

// Register is endpoint group for handler.
func (a *Application) Register(router chi.Router) {
	router.Route("/apps", func(r chi.Router) {
		r.Get("/", pkgRest.HandlerAdapter[ListApplicationsRequest](a.ListApplications).JSON)
		r.Post("/", pkgRest.HandlerAdapter[AddApplicationRequest](a.AddApplication).JSON)
		r.Route("/{id:[0-9A-Za-z-]+}", func(id chi.Router) {
			id.Get("/", pkgRest.HandlerAdapter[GetApplicationRequest](a.GetApplication).JSON)
			id.Put("/", pkgRest.HandlerAdapter[AddApplicationRequest](a.AddApplication).JSON)
			id.Delete("/", pkgRest.HandlerAdapter[DeleteApplicationRequest](a.DeleteApplication).JSON)
		})
	})
}

// ListApplications [GET /] applications endpoint func.
func (a *Application) ListApplications(w http.ResponseWriter, r *http.Request) (resp ListApplicationsResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "ListApplications")
		request          ListApplicationsRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[ListApplicationsRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind ListApplications")
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

	// applications, err = query.
	// 	Limit(request.Limit).
	// 	Offset(offset).
	// 	Order(ent.Desc(application.FieldID)).
	// 	Where(application.Or(
	// 		application.ApikeyContains(request.Query),
	// 	)).
	// 	All(ctxSpan)

	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	filter := bson.M{
		"id": int(userID),
	}
	findOptions := options.FindOne().SetProjection(bson.M{"applications": 1})
	var result ListApplicationsResponse
	err = collection.FindOne(ctxSpan, filter, findOptions).Decode(&result)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	// pagination
	pkgRest.Paging(r, pkgRest.Pagination{
		Page:  request.Page,
		Limit: request.Limit,
		Total: len(result.Applications),
	})
	// if err = copier.Copy(&rows, &applications); err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	// add apikey
	// for i := range rows {
	// 	rows[i].ApiKey = applications[i].Apikey
	// 	rows[i].UserID = int(userID)
	// }
	l.Info().Msg("ListApplications")
	return result, nil
}

// AddApplication [POST /] application endpoint func.
func (a *Application) AddApplication(w http.ResponseWriter, r *http.Request) (resp AddApplicationResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "AddApplication")
		request          AddApplicationRequest
		row              *ent.Application
		artcl            entity.Application
	)
	defer span.End()

	request, err = pkgRest.GetBind[AddApplicationRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind AddApplication")
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
	// upsert
	var client = a.Database.Application
	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	if request.ID > "" {
		// postgres
		row, err = client.
			UpdateOneID(request.ID).
			SetName(request.Name).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
		}
		// mongodb
		filter := bson.M{"id": int(userID)}
		updatedApp := bson.M{
			"id":     row.ID,
			"name":   request.Name,
			"apikey": row.Apikey,
		}
		update := bson.M{
			"$set": bson.M{
				"applications.$[elem]": updatedApp,
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
			SetID(generateApplicationID()).
			SetName(request.Name).
			SetApikey(generateAPIKey()).
			SetUserID(int(userID)).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
		}
		// mongodb
		filter := bson.M{"id": int(userID)}
		newApp := bson.D{
			{Key: "id", Value: row.ID},
			{Key: "name", Value: request.Name},
			{Key: "apikey", Value: row.Apikey},
		}
		update := bson.M{
			"$push": bson.M{
				"applications": newApp,
			},
		}
		_, err = collection.UpdateOne(ctxSpan, filter, update)
	}
	if err != nil {
		// if insert mongodb error, delete record in postgres
		client.
			DeleteOneID(row.ID).
			Exec(ctxSpan)
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	l.Info().Interface("Application", artcl).Msg("AddApplication")
	if err = copier.Copy(&artcl, &row); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	// add apikey
	artcl.ApiKey = row.Apikey
	artcl.UserID = int(userID)
	return AddApplicationResponse{
		Application: artcl,
	}, nil
}

// GetApplication [GET /:id] application endpoint func.
func (a *Application) GetApplication(w http.ResponseWriter, r *http.Request) (resp GetApplicationResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "GetApplication")
		request          GetApplicationRequest
		artcl            entity.Application
	)
	defer span.End()
	request, err = pkgRest.GetBind[GetApplicationRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind GetApplication")
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

	// row, errr := a.Database.Application.
	// 	Query().
	// 	Where(application.ID(request.ID)).
	// 	First(ctxSpan)

	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	filter := bson.M{
		"id":              int(userID), // Replace with the document's _id
		"applications.id": request.ID,  // Replace with the desired application ID
	}
	pipeline := bson.A{
		bson.M{"$match": filter},
		bson.M{"$unwind": "$applications"},
		bson.M{"$match": bson.M{"applications.id": request.ID}},
		bson.M{"$project": bson.M{
			"_id":    0,
			"id":     "$applications.id",
			"name":   "$applications.name",
			"apikey": "$applications.apikey",
		}},
	}
	cursor, err := collection.Aggregate(ctxSpan, pipeline)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	defer cursor.Close(ctxSpan)

	if cursor.Next(ctxSpan) {
		if err := cursor.Decode(&artcl); err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
		}
	} else {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("no matching document found"))
	}

	if err := cursor.Err(); err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}

	l.Info().Msg("GetApplicationRequest")
	// if err = copier.Copy(&artcl, &row); err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }

	// add apikey
	// artcl.ApiKey = row.Apikey
	artcl.UserID = int(userID)
	return GetApplicationResponse{
		Application: artcl,
	}, nil
}

// DeleteApplication [DELETE /:id] application endpoint func.
func (a *Application) DeleteApplication(w http.ResponseWriter, r *http.Request) (resp DeleteApplicationResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "DeleteApplication")
		request          DeleteApplicationRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[DeleteApplicationRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind DeleteApplication")
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

	var client = a.Database.Application
	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	if request.ID == "" {
		return resp, pkgRest.ErrBadRequest(w, r, errors.New("application id is required"))
	}
	// postgres
	err = client.
		DeleteOneID(request.ID).
		Exec(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	// mongodb
	filter := bson.M{
		"id": int(userID), // Replace with the document's _id
	}
	update := bson.M{
		"$pull": bson.M{
			"applications": bson.M{"id": request.ID},
		},
	}
	_, err = collection.UpdateOne(ctxSpan, filter, update)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}

	l.Info().Msg("DeleteApplicationRequest")
	return DeleteApplicationResponse{
		Message: fmt.Sprintf("application %s deleted", request.ID),
	}, nil
}
