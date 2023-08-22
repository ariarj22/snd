// Package rest is port handler.
package rest

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"entgo.io/ent/dialect"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/jinzhu/copier"
	pkgRest "github.com/kubuskotak/asgard/rest"
	pkgTracer "github.com/kubuskotak/asgard/tracer"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/kubuskotak/king/pkg/adapters"
	"github.com/kubuskotak/king/pkg/entity"
	"github.com/kubuskotak/king/pkg/infrastructure"
	"github.com/kubuskotak/king/pkg/persist/crud"
	"github.com/kubuskotak/king/pkg/persist/crud/ent"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/user"
)

// UserOption is a struct holding the handler options.
type UserOption func(user *User)

// User handler instance data.
type User struct {
	*crud.Database
	*mongo.Client
}

// WithUserDatabase option function to assign on user.
func WithUserDatabase(adapter *adapters.CrudPostgres) UserOption {
	return func(a *User) {
		a.Database = crud.Driver(crud.WithDriver(adapter.Client, dialect.Postgres))
	}
}

// WithUserMongoDB option function to assign on user.
func WithUserMongoDB(adapter *adapters.CrudMongoDB) UserOption {
	return func(a *User) {
		a.Client = adapter.Client
	}
}

// NewUser creates a new user handler instance.
//
//	var userHandler = rest.NewUser()
//
//	You can pass optional configuration options by passing a Config struct:
//
//	var adaptor = &adapters.Adapter{}
//	var userHandler = rest.NewUser(rest.WithUserAdapter(adaptor))
func NewUser(opts ...UserOption) *User {
	// Create a new handler.
	var handler = &User{}

	// Assign handler options.
	for o := range opts {
		var opt = opts[o]
		opt(handler)
	}

	// Return handler.
	return handler
}

// Register is endpoint group for handler.
func (a *User) Register(router chi.Router) {
	router.Route("/", func(r chi.Router) {
		r.Get("/", pkgRest.HandlerAdapter[ListUsersRequest](a.ListUsers).JSON)
		r.Post("/register", pkgRest.HandlerAdapter[RegisterUserRequest](a.RegisterUser).JSON)
		r.Post("/login", pkgRest.HandlerAdapter[LoginUserRequest](a.LoginUser).JSON)
		r.Post("/logout", pkgRest.HandlerAdapter[LogoutUserRequest](a.LogoutUser).JSON)
		r.Route("/{id:[0-9-]+}", func(id chi.Router) {
			id.Get("/", pkgRest.HandlerAdapter[GetUserRequest](a.GetUser).JSON)
			id.Put("/", pkgRest.HandlerAdapter[RegisterUserRequest](a.RegisterUser).JSON)
			id.Delete("/", pkgRest.HandlerAdapter[DeleteUserRequest](a.DeleteUser).JSON)
		})
	})
}

// ListUsers [GET /] users endpoint func.
func (a *User) ListUsers(w http.ResponseWriter, r *http.Request) (resp ListUsersResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "ListUsers")
		request          ListUsersRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[ListUsersRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind ListUsers")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	var (
		total  int
		query  = a.Database.User.Query()
		users  []*ent.User
		offset = (request.Page - 1) * request.Limit
		rows   = make([]*entity.User, len(users))
	)
	// pagination
	total, err = query.Count(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	pkgRest.Paging(r, pkgRest.Pagination{
		Page:  request.Page,
		Limit: request.Limit,
		Total: total,
	})
	users, err = query.
		Limit(request.Limit).
		Offset(offset).
		Order(ent.Asc(user.FieldID)).
		Where(user.Or(
			user.EmailContains(request.Query),
		)).
		All(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	if err = copier.Copy(&rows, &users); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	l.Info().Msg("ListUsers")
	return ListUsersResponse{
		Users: rows,
	}, nil
}

// RegisterUser [POST /register] upsert user endpoint func.
func (a *User) RegisterUser(w http.ResponseWriter, r *http.Request) (resp RegisterUserResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "RegisterUser")
		request          RegisterUserRequest
		row              *ent.User
		artcl            entity.User
	)
	defer span.End()
	request, err = pkgRest.GetBind[RegisterUserRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind RegisterUser")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	//  upsert
	var client = a.Database.User
	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	if request.ID > 0 {
		row, err = client.
			UpdateOneID(request.ID).
			SetEmail(request.Email).
			SetPassword(request.Password).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
		}
		err = collection.FindOne(ctxSpan, bson.M{"id": request.ID}).Decode(&artcl)
		if err != nil {
			_, err = collection.InsertOne(ctxSpan, bson.D{
				{Key: "id", Value: row.ID},
				{Key: "email", Value: request.Email},
				{Key: "password", Value: request.Password},
			})
		} else {
			_, err = collection.UpdateOne(ctxSpan, bson.M{"id": request.ID}, bson.M{"$set": bson.M{"email": request.Email, "password": request.Password}})
		}
	} else {
		row, err = client.
			Create().
			SetEmail(request.Email).
			SetPassword(request.Password).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
		}
		_, err = collection.InsertOne(ctxSpan, bson.D{
			{Key: "id", Value: row.ID},
			{Key: "email", Value: request.Email},
			{Key: "password", Value: request.Password},
		})
	}
	if err != nil {
		client.
			DeleteOneID(request.ID).
			Exec(ctxSpan)
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	l.Info().Interface("User", artcl).Msg("RegisterUser")
	if err = copier.Copy(&artcl, &row); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	return RegisterUserResponse{
		User: artcl,
	}, nil
}

// LoginUser [POST /login] user endpoint func.
func (a *User) LoginUser(w http.ResponseWriter, r *http.Request) (resp LoginUserResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "LoginUser")
		request          LoginUserRequest
		// row              *ent.User
		artcl entity.User
	)
	defer span.End()

	request, err = pkgRest.GetBind[LoginUserRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind LoginUser")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	// Retrieve user by email
	// client := a.Database.User
	// row, err = client.Query().Where(user.EmailEQ(request.Email)).Only(ctxSpan)
	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	err = collection.FindOne(ctxSpan, bson.M{"email": request.Email}).Decode(&artcl)
	if err != nil {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid email or password"))
	}

	// Check password
	if artcl.Password != request.Password {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid email or password"))
	}

	// Generate JWT token
	claims := jwt.MapClaims{
		"userID": artcl.ID,
		"exp":    time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
	if jwtSecretKey == "" {
		return resp, pkgRest.ErrInternalServerError(w, r, errors.New("JWT_SECRET_KEY not set"))
	}

	signedToken, err := token.SignedString([]byte(jwtSecretKey))

	// Store the JWT token in a cookie
	cookie := http.Cookie{
		Name:     "token",
		Value:    signedToken,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	l.Info().Str("UserID", fmt.Sprintf("%d", artcl.ID)).Msg("LoginUser")
	return LoginUserResponse{
		Message: fmt.Sprintf("login successful for user %d", artcl.ID),
	}, nil
}

// GetUser [GET :id] user endpoint func.
func (a *User) GetUser(w http.ResponseWriter, r *http.Request) (resp GetUserResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "GetUser")
		request          GetUserRequest
		// row              *ent.User
		artcl entity.User
	)
	defer span.End()
	request, err = pkgRest.GetBind[GetUserRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind GetUser")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	// row, err = a.Database.User.
	// 	Query().
	// 	Where(user.ID(request.Keys.ID)).
	// 	First(ctxSpan)
	database := a.Client.Database(infrastructure.Envs.CrudMongoDB.Database)
	collection := database.Collection(infrastructure.Envs.CrudMongoDB.Collection)
	err = collection.FindOne(ctxSpan, bson.M{"id": request.Keys.ID}).Decode(&artcl)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("got an error", err))
	}
	l.Info().Msg("GetUserRequest")
	// if err = copier.Copy(&artcl, &row); err != nil {
	// 	return resp, pkgRest.ErrBadRequest(w, r, err)
	// }
	return GetUserResponse{
		User: artcl,
	}, nil
}

// DeleteUser [DELETE :id] user endpoint func.
func (a *User) DeleteUser(w http.ResponseWriter, r *http.Request) (resp DeleteUserResponse, err error) {
	var (
		ctxSpan, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "DeleteUser")
		request          DeleteUserRequest
	)
	defer span.End()
	request, err = pkgRest.GetBind[DeleteUserRequest](r)
	if err != nil {
		l.Error().Err(err).Msg("Bind DeleteUser")
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	var client = a.Database.User
	if request.ID < 1 {
		return resp, pkgRest.ErrStatusConflict(w, r, errors.New("record id is"))
	}
	err = client.
		DeleteOneID(request.ID).
		Exec(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, a.Database.ConvertDBError("record", err))
	}
	return DeleteUserResponse{
		Message: fmt.Sprintf("record deleted successfully: %d", request.ID),
	}, nil
}

// LogoutUser [POST /logout] user endpoint func.
func (a *User) LogoutUser(w http.ResponseWriter, r *http.Request) (resp LogoutUserResponse, err error) {
	var (
		_, span, l = pkgTracer.StartSpanLogTrace(r.Context(), "LogoutUser")
	)
	defer span.End()

	// Check if the token exists
	userID := "0"
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			return resp, pkgRest.ErrUnauthorized(w, r, errors.New("unauthorized"))
		}
	}

	token, _ := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		jwtSecretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
		return jwtSecretKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if userIDClaim, exists := claims["userID"]; exists {
			if id, ok := userIDClaim.(float64); ok {
				userID = fmt.Sprintf("%.0f", id)
			}
		}
	}

	// Remove the JWT token by setting an expired cookie
	cookie := http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	l.Info().Str("UserID", userID).Msg("LogoutUser")
	return LogoutUserResponse{
		Message: "logout successful",
	}, nil
}
