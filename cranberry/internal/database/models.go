package database

import (
	"database/sql"

	"gorm.io/gorm"
)

type Proxy struct {
	gorm.Model
	UUID sql.NullString
	Name sql.NullString
}
