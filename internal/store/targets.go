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
	Name, User, Host, Path, Format, PostCmd string
	Resolve                                 bool
	HostKey                                 string
	PushedHash                              string
	PushedAt                                time.Time
}

func (t Target) validate() error {
	if err := validName(t.Name); err != nil {
		return err
	}
	if _, ok := formats.Formats[t.Format]; !ok {
		return fmt.Errorf("%w: format %q", ErrBadName, t.Format)
	}
	if t.User == "" || t.Host == "" || strings.ContainsAny(t.User+t.Host, " @/") {
		return fmt.Errorf("%w: user and host are required", ErrBadName)
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
		_, err := tx.Exec(`INSERT INTO targets(env_id,name,ssh_user,host,path,format,resolve,post_cmd)
		  VALUES(?,?,?,?,?,?,?,?)`, eid, t.Name, t.User, t.Host, t.Path, t.Format, t.Resolve, t.PostCmd)
		return mapExists(err)
	}, actor, "target.create", project+"/"+env+"/"+t.Name, t.User+"@"+t.Host+":"+t.Path)
}

const targetCols = `name,ssh_user,host,path,format,resolve,post_cmd,host_key,pushed_hash,pushed_at`

func scanTarget(sc interface{ Scan(...any) error }) (Target, error) {
	var t Target
	var pushedAt int64
	err := sc.Scan(&t.Name, &t.User, &t.Host, &t.Path, &t.Format, &t.Resolve, &t.PostCmd,
		&t.HostKey, &t.PushedHash, &pushedAt)
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
	rows, err := s.db.Query(`SELECT `+targetCols+` FROM targets WHERE env_id=? ORDER BY name`, eid)
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
	t, err := scanTarget(s.db.QueryRow(`SELECT `+targetCols+` FROM targets WHERE env_id=? AND name=?`, eid, name))
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

// PinHostKey never overwrites an existing pin.
func (s *Store) PinHostKey(project, env, name, hostKey, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`UPDATE targets SET host_key=? WHERE env_id=? AND name=? AND host_key=''`,
			hostKey, eid, name))
	}, actor, "target.pin", project+"/"+env+"/"+name, hostKey)
}

func (s *Store) ForgetHostKey(project, env, name, actor string) error {
	eid, err := s.envID(project, env)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`UPDATE targets SET host_key='' WHERE env_id=? AND name=?`, eid, name))
	}, actor, "target.unpin", project+"/"+env+"/"+name, "")
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
