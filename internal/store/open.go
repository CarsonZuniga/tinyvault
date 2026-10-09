package store

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const driverName = "sqlite"

func Open(path string, key []byte) (*Store, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, err
	}
	s, err := New(db, key)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
