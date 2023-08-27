package entity

type Index struct {
	ID            int    `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	ApplicationID string `json:"applicationid,omitempty"`
}
