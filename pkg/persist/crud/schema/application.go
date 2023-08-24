package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Application holds the schema definition for the Application entity.
type Application struct {
	ent.Schema
}

// Fields of the Application.
func (Application) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			Unique(),
		field.String("name").
			Unique(),
		field.String("apikey").
			Unique(),
	}
}

// Edges of the Application.
func (Application) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("applications").
			Unique(),
		edge.To("indexes", Index.Type),
	}
}
