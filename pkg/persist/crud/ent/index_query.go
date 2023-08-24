// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/application"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/index"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/predicate"
)

// IndexQuery is the builder for querying Index entities.
type IndexQuery struct {
	config
	ctx             *QueryContext
	order           []index.OrderOption
	inters          []Interceptor
	predicates      []predicate.Index
	withApplication *ApplicationQuery
	withFKs         bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the IndexQuery builder.
func (iq *IndexQuery) Where(ps ...predicate.Index) *IndexQuery {
	iq.predicates = append(iq.predicates, ps...)
	return iq
}

// Limit the number of records to be returned by this query.
func (iq *IndexQuery) Limit(limit int) *IndexQuery {
	iq.ctx.Limit = &limit
	return iq
}

// Offset to start from.
func (iq *IndexQuery) Offset(offset int) *IndexQuery {
	iq.ctx.Offset = &offset
	return iq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (iq *IndexQuery) Unique(unique bool) *IndexQuery {
	iq.ctx.Unique = &unique
	return iq
}

// Order specifies how the records should be ordered.
func (iq *IndexQuery) Order(o ...index.OrderOption) *IndexQuery {
	iq.order = append(iq.order, o...)
	return iq
}

// QueryApplication chains the current query on the "application" edge.
func (iq *IndexQuery) QueryApplication() *ApplicationQuery {
	query := (&ApplicationClient{config: iq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := iq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := iq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(index.Table, index.FieldID, selector),
			sqlgraph.To(application.Table, application.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, index.ApplicationTable, index.ApplicationColumn),
		)
		fromU = sqlgraph.SetNeighbors(iq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Index entity from the query.
// Returns a *NotFoundError when no Index was found.
func (iq *IndexQuery) First(ctx context.Context) (*Index, error) {
	nodes, err := iq.Limit(1).All(setContextOp(ctx, iq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{index.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (iq *IndexQuery) FirstX(ctx context.Context) *Index {
	node, err := iq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Index ID from the query.
// Returns a *NotFoundError when no Index ID was found.
func (iq *IndexQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = iq.Limit(1).IDs(setContextOp(ctx, iq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{index.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (iq *IndexQuery) FirstIDX(ctx context.Context) int {
	id, err := iq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Index entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Index entity is found.
// Returns a *NotFoundError when no Index entities are found.
func (iq *IndexQuery) Only(ctx context.Context) (*Index, error) {
	nodes, err := iq.Limit(2).All(setContextOp(ctx, iq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{index.Label}
	default:
		return nil, &NotSingularError{index.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (iq *IndexQuery) OnlyX(ctx context.Context) *Index {
	node, err := iq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Index ID in the query.
// Returns a *NotSingularError when more than one Index ID is found.
// Returns a *NotFoundError when no entities are found.
func (iq *IndexQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = iq.Limit(2).IDs(setContextOp(ctx, iq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{index.Label}
	default:
		err = &NotSingularError{index.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (iq *IndexQuery) OnlyIDX(ctx context.Context) int {
	id, err := iq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Indexes.
func (iq *IndexQuery) All(ctx context.Context) ([]*Index, error) {
	ctx = setContextOp(ctx, iq.ctx, "All")
	if err := iq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Index, *IndexQuery]()
	return withInterceptors[[]*Index](ctx, iq, qr, iq.inters)
}

// AllX is like All, but panics if an error occurs.
func (iq *IndexQuery) AllX(ctx context.Context) []*Index {
	nodes, err := iq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Index IDs.
func (iq *IndexQuery) IDs(ctx context.Context) (ids []int, err error) {
	if iq.ctx.Unique == nil && iq.path != nil {
		iq.Unique(true)
	}
	ctx = setContextOp(ctx, iq.ctx, "IDs")
	if err = iq.Select(index.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (iq *IndexQuery) IDsX(ctx context.Context) []int {
	ids, err := iq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (iq *IndexQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, iq.ctx, "Count")
	if err := iq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, iq, querierCount[*IndexQuery](), iq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (iq *IndexQuery) CountX(ctx context.Context) int {
	count, err := iq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (iq *IndexQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, iq.ctx, "Exist")
	switch _, err := iq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (iq *IndexQuery) ExistX(ctx context.Context) bool {
	exist, err := iq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the IndexQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (iq *IndexQuery) Clone() *IndexQuery {
	if iq == nil {
		return nil
	}
	return &IndexQuery{
		config:          iq.config,
		ctx:             iq.ctx.Clone(),
		order:           append([]index.OrderOption{}, iq.order...),
		inters:          append([]Interceptor{}, iq.inters...),
		predicates:      append([]predicate.Index{}, iq.predicates...),
		withApplication: iq.withApplication.Clone(),
		// clone intermediate query.
		sql:  iq.sql.Clone(),
		path: iq.path,
	}
}

// WithApplication tells the query-builder to eager-load the nodes that are connected to
// the "application" edge. The optional arguments are used to configure the query builder of the edge.
func (iq *IndexQuery) WithApplication(opts ...func(*ApplicationQuery)) *IndexQuery {
	query := (&ApplicationClient{config: iq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	iq.withApplication = query
	return iq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Index.Query().
//		GroupBy(index.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (iq *IndexQuery) GroupBy(field string, fields ...string) *IndexGroupBy {
	iq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &IndexGroupBy{build: iq}
	grbuild.flds = &iq.ctx.Fields
	grbuild.label = index.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//	}
//
//	client.Index.Query().
//		Select(index.FieldName).
//		Scan(ctx, &v)
func (iq *IndexQuery) Select(fields ...string) *IndexSelect {
	iq.ctx.Fields = append(iq.ctx.Fields, fields...)
	sbuild := &IndexSelect{IndexQuery: iq}
	sbuild.label = index.Label
	sbuild.flds, sbuild.scan = &iq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a IndexSelect configured with the given aggregations.
func (iq *IndexQuery) Aggregate(fns ...AggregateFunc) *IndexSelect {
	return iq.Select().Aggregate(fns...)
}

func (iq *IndexQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range iq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, iq); err != nil {
				return err
			}
		}
	}
	for _, f := range iq.ctx.Fields {
		if !index.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if iq.path != nil {
		prev, err := iq.path(ctx)
		if err != nil {
			return err
		}
		iq.sql = prev
	}
	return nil
}

func (iq *IndexQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Index, error) {
	var (
		nodes       = []*Index{}
		withFKs     = iq.withFKs
		_spec       = iq.querySpec()
		loadedTypes = [1]bool{
			iq.withApplication != nil,
		}
	)
	if iq.withApplication != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, index.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Index).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Index{config: iq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, iq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := iq.withApplication; query != nil {
		if err := iq.loadApplication(ctx, query, nodes, nil,
			func(n *Index, e *Application) { n.Edges.Application = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (iq *IndexQuery) loadApplication(ctx context.Context, query *ApplicationQuery, nodes []*Index, init func(*Index), assign func(*Index, *Application)) error {
	ids := make([]string, 0, len(nodes))
	nodeids := make(map[string][]*Index)
	for i := range nodes {
		if nodes[i].application_indexes == nil {
			continue
		}
		fk := *nodes[i].application_indexes
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(application.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "application_indexes" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (iq *IndexQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := iq.querySpec()
	_spec.Node.Columns = iq.ctx.Fields
	if len(iq.ctx.Fields) > 0 {
		_spec.Unique = iq.ctx.Unique != nil && *iq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, iq.driver, _spec)
}

func (iq *IndexQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(index.Table, index.Columns, sqlgraph.NewFieldSpec(index.FieldID, field.TypeInt))
	_spec.From = iq.sql
	if unique := iq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if iq.path != nil {
		_spec.Unique = true
	}
	if fields := iq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, index.FieldID)
		for i := range fields {
			if fields[i] != index.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := iq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := iq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := iq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := iq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (iq *IndexQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(iq.driver.Dialect())
	t1 := builder.Table(index.Table)
	columns := iq.ctx.Fields
	if len(columns) == 0 {
		columns = index.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if iq.sql != nil {
		selector = iq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if iq.ctx.Unique != nil && *iq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range iq.predicates {
		p(selector)
	}
	for _, p := range iq.order {
		p(selector)
	}
	if offset := iq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := iq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// IndexGroupBy is the group-by builder for Index entities.
type IndexGroupBy struct {
	selector
	build *IndexQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (igb *IndexGroupBy) Aggregate(fns ...AggregateFunc) *IndexGroupBy {
	igb.fns = append(igb.fns, fns...)
	return igb
}

// Scan applies the selector query and scans the result into the given value.
func (igb *IndexGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, igb.build.ctx, "GroupBy")
	if err := igb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IndexQuery, *IndexGroupBy](ctx, igb.build, igb, igb.build.inters, v)
}

func (igb *IndexGroupBy) sqlScan(ctx context.Context, root *IndexQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(igb.fns))
	for _, fn := range igb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*igb.flds)+len(igb.fns))
		for _, f := range *igb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*igb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := igb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// IndexSelect is the builder for selecting fields of Index entities.
type IndexSelect struct {
	*IndexQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (is *IndexSelect) Aggregate(fns ...AggregateFunc) *IndexSelect {
	is.fns = append(is.fns, fns...)
	return is
}

// Scan applies the selector query and scans the result into the given value.
func (is *IndexSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, is.ctx, "Select")
	if err := is.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IndexQuery, *IndexSelect](ctx, is.IndexQuery, is, is.inters, v)
}

func (is *IndexSelect) sqlScan(ctx context.Context, root *IndexQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(is.fns))
	for _, fn := range is.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*is.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := is.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
