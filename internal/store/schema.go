package store

import (
	"database/sql"
	"fmt"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS environments (
  id INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL, created_at INTEGER NOT NULL,
  UNIQUE(project_id, name));
CREATE TABLE IF NOT EXISTS secret_versions (
  id INTEGER PRIMARY KEY,
  env_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  key TEXT NOT NULL, version INTEGER NOT NULL,
  value BLOB, deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, actor TEXT NOT NULL,
  UNIQUE(env_id, key, version));
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
`

// migrations[i] moves the database from user_version i to i+1.
var migrations = []string{
	`DROP TABLE IF EXISTS targets;
CREATE TABLE hosts (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  ssh_user TEXT NOT NULL, address TEXT NOT NULL, host_key TEXT NOT NULL DEFAULT '');
CREATE TABLE targets (
  id INTEGER PRIMARY KEY,
  env_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
  name TEXT NOT NULL, path TEXT NOT NULL,
  format TEXT NOT NULL, resolve INTEGER NOT NULL, post_cmd TEXT NOT NULL,
  pushed_hash TEXT NOT NULL DEFAULT '', pushed_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(env_id, name), UNIQUE(host_id, path));`,
}

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for ; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
