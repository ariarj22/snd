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

	pkgRest "github.com/kubuskotak/asgard/rest"
	pkgTracer "github.com/kubuskotak/asgard/tracer"
	"github.com/kubuskotak/king/pkg/adapters"
	"github.com/kubuskotak/king/pkg/entity"
	"github.com/kubuskotak/king/pkg/persist/crud"
	"github.com/kubuskotak/king/pkg/persist/crud/ent"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/index"
)

// IndexOption is a struct holding the handler options.
type IndexOption func(index *Index)

// Index handler instance data.
type Index struct {
	*crud.Database
}

// WithIndexDatabase option function to assign on Index.
func WithIndexDatabase(adapter *adapters.CrudPostgres) IndexOption {
	return func(h *Index) {
		h.Database = crud.Driver(crud.WithDriver(adapter.Client, dialect.Postgres))
	}
}

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

	_, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	if err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	var (
		total   int
		query   = h.Database.Index.Query()
		indexes []*ent.Index
		offset  = (request.Page - 1) * request.Limit
		rows    = make([]*entity.Index, len(indexes))
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
	indexes, err = query.
		Limit(request.Limit).
		Offset(offset).
		Order(ent.Desc(index.FieldName)).
		Where(index.Or(
			index.NameContains(request.Query),
		)).
		All(ctxSpan)

	if err = copier.Copy(&rows, &indexes); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}
	
	l.Info().Msg("ListIndexes")
	return ListIndexesResponse{
		Indexes: rows,
	}, nil
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

	_, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	var client = h.Database.Index
	if request.ID > 0 {
		row, err = client.
			UpdateOneID(request.ID).
			SetName(request.Name).
			SetApplicationID(SelectedApplicationID).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
	} else {
		row, err = client.
			Create().
			SetName(request.Name).
			SetApplicationID(SelectedApplicationID).
			Save(ctxSpan)
		if err != nil {
			return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
		}
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
		row              *ent.Index
		artcl            entity.Index
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

	_, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	var client = h.Database.Index
	row, err = client.
		Query().
		Where(index.Name(request.ID)).
		First(ctxSpan)
	if err != nil {
		return resp, pkgRest.ErrStatusConflict(w, r, h.Database.ConvertDBError("got an error", err))
	}
	l.Info().Msg("GetIndexRequest")
	if err = copier.Copy(&artcl, &row); err != nil {
		return resp, pkgRest.ErrBadRequest(w, r, err)
	}

	artcl.ApplicationID = SelectedApplicationID
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

	_, ok := claims["userID"].(float64)
	if !ok {
		return resp, pkgRest.ErrUnauthorized(w, r, errors.New("invalid user ID in token"))
	}

	var client = h.Database.Index
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

	l.Info().Msg("DeleteIndexRequest")
	return DeleteIndexResponse{
		Message: fmt.Sprintf("Index %s deleted", request.ID),
	}, nil
}
