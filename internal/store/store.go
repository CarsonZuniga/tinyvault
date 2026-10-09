package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/carsonzuniga/tinyvault/internal/crypto"
	"github.com/carsonzuniga/tinyvault/internal/formats"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrBadName  = errors.New("invalid name")
	ErrWrongKey = errors.New("master key does not match this database")
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type Store struct {
	db  *sql.DB
	box *crypto.Box
}

type Version struct {
	Version   int
	CreatedAt time.Time
	Actor     string
	Deleted   bool
}

type AuditEntry struct {
	TS     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

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

func New(db *sql.DB, key []byte) (*Store, error) {
	box, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	// One connection: simple, avoids SQLITE_BUSY, and fine for a tiny admin app.
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL",
	} {
		if _, err := db.Exec(p); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	fp := crypto.Fingerprint(key)
	var have string
	err = db.QueryRow(`SELECT v FROM meta WHERE k='key_fp'`).Scan(&have)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.Exec(`INSERT INTO meta(k,v) VALUES('key_fp',?)`, fp); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case have != fp:
		return nil, ErrWrongKey
	}
	return &Store{db: db, box: box}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func aad(project, env, key string) string { return project + "/" + env + "/" + key }

func validName(n string) error {
	if !nameRe.MatchString(n) {
		return fmt.Errorf("%w: %q (use a-z, 0-9, _ or -)", ErrBadName, n)
	}
	return nil
}

func (s *Store) CreateProject(name, actor string) error {
	if err := validName(name); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO projects(name,created_at) VALUES(?,?)`, name, time.Now().Unix())
	if err != nil {
		return mapExists(err)
	}
	return s.Audit(actor, "project.create", name, "")
}

func (s *Store) ListProjects() ([]string, error) {
	return s.names(`SELECT name FROM projects ORDER BY name`)
}

func (s *Store) DeleteProject(name, actor string) error {
	r, err := s.db.Exec(`DELETE FROM projects WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.Audit(actor, "project.delete", name, "")
}

func (s *Store) CreateEnv(project, env, actor string) error {
	if err := validName(env); err != nil {
		return err
	}
	pid, err := s.projectID(project)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO environments(project_id,name,created_at) VALUES(?,?,?)`,
		pid, env, time.Now().Unix()); err != nil {
		return mapExists(err)
	}
	return s.Audit(actor, "env.create", project+"/"+env, "")
}

func (s *Store) ListEnvs(project string) ([]string, error) {
	pid, err := s.projectID(project)
	if err != nil {
		return nil, err
	}
	return s.names(`SELECT name FROM environments WHERE project_id=? ORDER BY name`, pid)
}

func (s *Store) DeleteEnv(project, env, actor string) error {
	pid, err := s.projectID(project)
	if err != nil {
		return err
	}
	r, err := s.db.Exec(`DELETE FROM environments WHERE project_id=? AND name=?`, pid, env)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.Audit(actor, "env.delete", project+"/"+env, "")
}

func (s *Store) Set(project, env, key, value, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.setTx(tx, project, env, key, value, actor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Audit(actor, "secret.set", aad(project, env, key), "")
}

func (s *Store) Import(project, env string, kv map[string]string, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range kv {
		if err := s.setTx(tx, project, env, k, v, actor); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Audit(actor, "secret.import", project+"/"+env, fmt.Sprintf("%d keys", len(kv)))
}

func (s *Store) setTx(tx *sql.Tx, project, env, key, value, actor string) error {
	if !formats.ValidKey(key) {
		return fmt.Errorf("%w: key %q", ErrBadName, key)
	}
	eid, err := s.envIDTx(tx, project, env)
	if err != nil {
		return err
	}
	ct, err := s.box.Seal([]byte(value), aad(project, env, key))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO secret_versions(env_id,key,version,value,deleted,created_at,actor)
	  VALUES(?,?,COALESCE((SELECT MAX(version) FROM secret_versions WHERE env_id=? AND key=?),0)+1,?,0,?,?)`,
		eid, key, eid, key, ct, time.Now().Unix(), actor)
	return err
}

func (s *Store) Get(project, env, key, actor string) (string, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return "", err
	}
	var ct []byte
	var deleted int
	err = s.db.QueryRow(`SELECT value,deleted FROM secret_versions
	  WHERE env_id=? AND key=? ORDER BY version DESC LIMIT 1`, eid, key).Scan(&ct, &deleted)
	if errors.Is(err, sql.ErrNoRows) || deleted == 1 {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	pt, err := s.box.Open(ct, aad(project, env, key))
	if err != nil {
		return "", err
	}
	if err := s.Audit(actor, "secret.reveal", aad(project, env, key), ""); err != nil {
		return "", err
	}
	return string(pt), nil
}

func (s *Store) Keys(project, env string) ([]string, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return nil, err
	}
	return s.names(`SELECT key FROM secret_versions v WHERE env_id=? AND deleted=0
	  AND version=(SELECT MAX(version) FROM secret_versions WHERE env_id=v.env_id AND key=v.key)
	  ORDER BY key`, eid)
}

func (s *Store) GetAll(project, env, actor string) (map[string]string, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT key,value FROM secret_versions v WHERE env_id=? AND deleted=0
	  AND version=(SELECT MAX(version) FROM secret_versions WHERE env_id=v.env_id AND key=v.key)`, eid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k string
		var ct []byte
		if err := rows.Scan(&k, &ct); err != nil {
			return nil, err
		}
		pt, err := s.box.Open(ct, aad(project, env, k))
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", k, err)
		}
		out[k] = string(pt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.Audit(actor, "secret.export", project+"/"+env, fmt.Sprintf("%d keys", len(out)))
}

// Delete adds a tombstone version, so history survives and rollback works.
func (s *Store) Delete(project, env, key, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ver, deleted int
	err = tx.QueryRow(`SELECT version,deleted FROM secret_versions
	  WHERE env_id=? AND key=? ORDER BY version DESC LIMIT 1`, eid, key).Scan(&ver, &deleted)
	if errors.Is(err, sql.ErrNoRows) || deleted == 1 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO secret_versions(env_id,key,version,value,deleted,created_at,actor)
	  VALUES(?,?,?,NULL,1,?,?)`, eid, key, ver+1, time.Now().Unix(), actor); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Audit(actor, "secret.delete", aad(project, env, key), "")
}

func (s *Store) History(project, env, key string) ([]Version, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT version,created_at,actor,deleted FROM secret_versions
	  WHERE env_id=? AND key=? ORDER BY version DESC`, eid, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var ts int64
		var d int
		if err := rows.Scan(&v.Version, &ts, &v.Actor, &d); err != nil {
			return nil, err
		}
		v.CreatedAt, v.Deleted = time.Unix(ts, 0), d == 1
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, rows.Err()
}

func (s *Store) Rollback(project, env, key string, version int, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	var ct []byte
	var deleted int
	err = s.db.QueryRow(`SELECT value,deleted FROM secret_versions WHERE env_id=? AND key=? AND version=?`,
		eid, key, version).Scan(&ct, &deleted)
	if errors.Is(err, sql.ErrNoRows) || deleted == 1 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	pt, err := s.box.Open(ct, aad(project, env, key))
	if err != nil {
		return err
	}
	if err := s.Set(project, env, key, string(pt), actor); err != nil {
		return err
	}
	return s.Audit(actor, "secret.rollback", aad(project, env, key), fmt.Sprintf("to v%d", version))
}

func (s *Store) Audit(actor, action, target, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), actor, action, target, detail)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT ts,actor,action,target,detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &a.Actor, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		a.TS = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) projectID(name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM projects WHERE name=?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) envID(project, env string) (int64, error) { return s.envIDQ(s.db, project, env) }

func (s *Store) envIDTx(tx *sql.Tx, project, env string) (int64, error) {
	return s.envIDQ(tx, project, env)
}

type queryer interface {
	QueryRow(q string, args ...any) *sql.Row
}

func (s *Store) envIDQ(q queryer, project, env string) (int64, error) {
	var id int64
	err := q.QueryRow(`SELECT e.id FROM environments e JOIN projects p ON p.id=e.project_id
	  WHERE p.name=? AND e.name=?`, project, env).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) names(q string, args ...any) ([]string, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func mapExists(err error) error {
	if err != nil && regexp.MustCompile(`(?i)unique|constraint`).MatchString(err.Error()) {
		return ErrExists
	}
	return err
}
