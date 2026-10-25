package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/carsonzuniga/tinyvault/internal/formats"
)

type Target struct {
	Name, Path, Format, PostCmd string
	Resolve                     bool
	Host                        Host
	PushedHash                  string
	PushedAt                    time.Time
}

func (t Target) validate() error {
	if err := validName(t.Name); err != nil {
		return err
	}
	if _, ok := formats.Formats[t.Format]; !ok {
		return fmt.Errorf("%w: format %q", ErrBadName, t.Format)
	}
	if !strings.HasPrefix(t.Path, "/") || strings.HasSuffix(t.Path, "/") {
		return fmt.Errorf("%w: path must be an absolute file path", ErrBadName)
	}
	return nil
}

func (s *Store) CreateTarget(project, env string, t Target, actor string) error {
	if err := t.validate(); err != nil {
		return err
	}
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		var hid int64
		err := tx.QueryRow(`SELECT id FROM hosts WHERE name=?`, t.Host.Name).Scan(&hid)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: unknown host %q", ErrBadName, t.Host.Name)
		}
		if err != nil {
			return err
		}
		var other string
		err = tx.QueryRow(`SELECT p.name||'/'||e.name||'/'||t.name FROM targets t
		  JOIN environments e ON e.id=t.env_id JOIN projects p ON p.id=e.project_id
		  WHERE t.host_id=? AND t.path=?`, hid, t.Path).Scan(&other)
		switch {
		case err == nil:
			return fmt.Errorf("%s on %s is %w by %s", t.Path, t.Host.Name, ErrInUse, other)
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		_, err = tx.Exec(`INSERT INTO targets(env_id,host_id,name,path,format,resolve,post_cmd)
		  VALUES(?,?,?,?,?,?,?)`, eid, hid, t.Name, t.Path, t.Format, t.Resolve, t.PostCmd)
		return mapExists(err)
	}, actor, "target.create", project+"/"+env+"/"+t.Name, t.Host.Name+":"+t.Path)
}

const targetQuery = `SELECT t.name,t.path,t.format,t.resolve,t.post_cmd,t.pushed_hash,t.pushed_at,
  h.name,h.ssh_user,h.address,h.host_key FROM targets t JOIN hosts h ON h.id=t.host_id`

func scanTarget(sc interface{ Scan(...any) error }) (Target, error) {
	var t Target
	var pushedAt int64
	err := sc.Scan(&t.Name, &t.Path, &t.Format, &t.Resolve, &t.PostCmd, &t.PushedHash, &pushedAt,
		&t.Host.Name, &t.Host.User, &t.Host.Address, &t.Host.HostKey)
	if pushedAt > 0 {
		t.PushedAt = time.Unix(pushedAt, 0)
	}
	return t, err
}

func (s *Store) ListTargets(project, env string) ([]Target, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(targetQuery+` WHERE t.env_id=? ORDER BY t.name`, eid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTarget(project, env, name string) (Target, error) {
	eid, err := s.envID(project, env)
	if err != nil {
		return Target{}, err
	}
	t, err := scanTarget(s.db.QueryRow(targetQuery+` WHERE t.env_id=? AND t.name=?`, eid, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	return t, err
}

func (s *Store) DeleteTarget(project, env, name, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`DELETE FROM targets WHERE env_id=? AND name=?`, eid, name))
	}, actor, "target.delete", project+"/"+env+"/"+name, "")
}

// PinHostKey pins the key on the target's host and never overwrites an existing pin.
func (s *Store) PinHostKey(project, env, name, hostKey, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`UPDATE hosts SET host_key=? WHERE host_key=''
		  AND id=(SELECT host_id FROM targets WHERE env_id=? AND name=?)`, hostKey, eid, name))
	}, actor, "target.pin", project+"/"+env+"/"+name, hostKey)
}

func (s *Store) RecordPush(project, env, name, hash, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`UPDATE targets SET pushed_hash=?, pushed_at=? WHERE env_id=? AND name=?`,
			hash, time.Now().Unix(), eid, name))
	}, actor, "target.push", project+"/"+env+"/"+name, "")
}
