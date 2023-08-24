// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// ApplicationsColumns holds the columns for the "applications" table.
	ApplicationsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "apikey", Type: field.TypeString, Unique: true},
		{Name: "user_applications", Type: field.TypeInt, Nullable: true},
	}
	// ApplicationsTable holds the schema information for the "applications" table.
	ApplicationsTable = &schema.Table{
		Name:       "applications",
		Columns:    ApplicationsColumns,
		PrimaryKey: []*schema.Column{ApplicationsColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "applications_users_applications",
				Columns:    []*schema.Column{ApplicationsColumns[3]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// ArticlesColumns holds the columns for the "articles" table.
	ArticlesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "title", Type: field.TypeString, Default: ""},
		{Name: "body", Type: field.TypeString, Default: ""},
		{Name: "description", Type: field.TypeString, Default: ""},
		{Name: "slug", Type: field.TypeString, Unique: true},
		{Name: "user_id", Type: field.TypeInt, Nullable: true},
	}
	// ArticlesTable holds the schema information for the "articles" table.
	ArticlesTable = &schema.Table{
		Name:       "articles",
		Columns:    ArticlesColumns,
		PrimaryKey: []*schema.Column{ArticlesColumns[0]},
	}
	// IndexesColumns holds the columns for the "indexes" table.
	IndexesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "application_indexes", Type: field.TypeString, Nullable: true},
	}
	// IndexesTable holds the schema information for the "indexes" table.
	IndexesTable = &schema.Table{
		Name:       "indexes",
		Columns:    IndexesColumns,
		PrimaryKey: []*schema.Column{IndexesColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "indexes_applications_indexes",
				Columns:    []*schema.Column{IndexesColumns[2]},
				RefColumns: []*schema.Column{ApplicationsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "email", Type: field.TypeString, Unique: true},
		{Name: "password", Type: field.TypeString},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// YmirsColumns holds the columns for the "ymirs" table.
	YmirsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "version", Type: field.TypeString, Default: "alpha-test-dev1"},
	}
	// YmirsTable holds the schema information for the "ymirs" table.
	YmirsTable = &schema.Table{
		Name:       "ymirs",
		Columns:    YmirsColumns,
		PrimaryKey: []*schema.Column{YmirsColumns[0]},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		ApplicationsTable,
		ArticlesTable,
		IndexesTable,
		UsersTable,
		YmirsTable,
	}
)

func init() {
	ApplicationsTable.ForeignKeys[0].RefTable = UsersTable
	IndexesTable.ForeignKeys[0].RefTable = ApplicationsTable
}
