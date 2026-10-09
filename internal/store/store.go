package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

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
	db     *sql.DB
	box    *crypto.Box
	sshKey ed25519.PrivateKey
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
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  env_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  name TEXT NOT NULL, ssh_user TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL,
  format TEXT NOT NULL, resolve INTEGER NOT NULL, post_cmd TEXT NOT NULL,
  host_key TEXT NOT NULL DEFAULT '', pushed_hash TEXT NOT NULL DEFAULT '',
  pushed_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE(env_id, name));
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
`

func Open(path string, key []byte) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s, err := open(db, key)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func open(db *sql.DB, key []byte) (*Store, error) {
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
	s := &Store{db: db, box: box}
	fp := crypto.Fingerprint(key)
	have, err := s.meta("key_fp")
	switch {
	case errors.Is(err, ErrNotFound):
		if err := s.setMeta("key_fp", fp); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case have != fp:
		return nil, ErrWrongKey
	}
	if s.sshKey, err = s.loadSSHKey(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SSHKey() ed25519.PrivateKey { return s.sshKey }

func (s *Store) loadSSHKey() (ed25519.PrivateKey, error) {
	const aad = "meta/ssh_key"
	enc, err := s.meta("ssh_key")
	if errors.Is(err, ErrNotFound) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		ct, err := s.box.Seal(seed, aad)
		if err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), s.setMeta("ssh_key", base64.StdEncoding.EncodeToString(ct))
	}
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	seed, err := s.box.Open(ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt ssh key: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *Store) meta(k string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) setMeta(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO meta(k,v) VALUES(?,?)`, k, v)
	return err
}

func aad(project, env, key string) string { return project + "/" + env + "/" + key }

func validName(n string) error {
	if !nameRe.MatchString(n) {
		return fmt.Errorf("%w: %q (use a-z, 0-9, _ or -)", ErrBadName, n)
	}
	return nil
}

type execer interface {
	Exec(q string, args ...any) (sql.Result, error)
}

func audit(e execer, actor, action, target, detail string) error {
	_, err := e.Exec(`INSERT INTO audit(ts,actor,action,target,detail) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), actor, action, target, detail)
	return err
}

func (s *Store) Audit(actor, action, target, detail string) error {
	return audit(s.db, actor, action, target, detail)
}

func (s *Store) write(fn func(tx *sql.Tx) error, actor, action, target, detail string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := audit(tx, actor, action, target, detail); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateProject(name, actor string) error {
	if err := validName(name); err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO projects(name,created_at) VALUES(?,?)`, name, time.Now().Unix())
		return mapExists(err)
	}, actor, "project.create", name, "")
}

func (s *Store) ListProjects() ([]string, error) {
	return s.names(`SELECT name FROM projects ORDER BY name`)
}

func (s *Store) DeleteProject(name, actor string) error {
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`DELETE FROM projects WHERE name=?`, name))
	}, actor, "project.delete", name, "")
}

func (s *Store) CreateEnv(project, env, actor string) error {
	if err := validName(env); err != nil {
		return err
	}
	pid, err := s.projectID(project)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO environments(project_id,name,created_at) VALUES(?,?,?)`,
			pid, env, time.Now().Unix())
		return mapExists(err)
	}, actor, "env.create", project+"/"+env, "")
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
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`DELETE FROM environments WHERE project_id=? AND name=?`, pid, env))
	}, actor, "env.delete", project+"/"+env, "")
}

func (s *Store) Set(project, env, key, value, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return s.insertVersion(tx, eid, project, env, key, value, actor)
	}, actor, "secret.set", aad(project, env, key), "")
}

func (s *Store) Import(project, env string, kv map[string]string, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		for k, v := range kv {
			if err := s.insertVersion(tx, eid, project, env, k, v, actor); err != nil {
				return err
			}
		}
		return nil
	}, actor, "secret.import", project+"/"+env, fmt.Sprintf("%d keys", len(kv)))
}

func (s *Store) insertVersion(tx *sql.Tx, eid int64, project, env, key, value, actor string) error {
	if !formats.ValidKey(key) {
		return fmt.Errorf("%w: key %q", ErrBadName, key)
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
	var deleted bool
	err = s.db.QueryRow(`SELECT value,deleted FROM secret_versions
	  WHERE env_id=? AND key=? ORDER BY version DESC LIMIT 1`, eid, key).Scan(&ct, &deleted)
	if errors.Is(err, sql.ErrNoRows) || deleted {
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

// GetAll does not audit; callers record how the values were used.
func (s *Store) GetAll(project, env string) (map[string]string, error) {
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
	return out, rows.Err()
}

// Delete adds a tombstone version, so history survives and rollback works.
func (s *Store) Delete(project, env, key, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		var ver int
		var deleted bool
		err := tx.QueryRow(`SELECT version,deleted FROM secret_versions
		  WHERE env_id=? AND key=? ORDER BY version DESC LIMIT 1`, eid, key).Scan(&ver, &deleted)
		if errors.Is(err, sql.ErrNoRows) || deleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO secret_versions(env_id,key,version,value,deleted,created_at,actor)
		  VALUES(?,?,?,NULL,1,?,?)`, eid, key, ver+1, time.Now().Unix(), actor)
		return err
	}, actor, "secret.delete", aad(project, env, key), "")
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
		if err := rows.Scan(&v.Version, &ts, &v.Actor, &v.Deleted); err != nil {
			return nil, err
		}
		v.CreatedAt = time.Unix(ts, 0)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (s *Store) Rollback(project, env, key string, version int, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		var ct []byte
		var deleted bool
		err := tx.QueryRow(`SELECT value,deleted FROM secret_versions WHERE env_id=? AND key=? AND version=?`,
			eid, key, version).Scan(&ct, &deleted)
		if errors.Is(err, sql.ErrNoRows) || deleted {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		pt, err := s.box.Open(ct, aad(project, env, key))
		if err != nil {
			return err
		}
		return s.insertVersion(tx, eid, project, env, key, string(pt), actor)
	}, actor, "secret.rollback", aad(project, env, key), fmt.Sprintf("to v%d", version))
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

func (s *Store) envID(project, env string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT e.id FROM environments e JOIN projects p ON p.id=e.project_id
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
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrExists
	}
	return err
}

func mustAffect(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
