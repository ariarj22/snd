package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Index holds the schema definition for the Index entity.
type Index struct {
	ent.Schema
}

// Fields of the Index.
func (Index) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique(),
	}
}

// Edges of the Index.
func (Index) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("application", Application.Type).
			Ref("indexes").
			Unique(),
	}
}
