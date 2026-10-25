package store

import (
	"database/sql"
	"fmt"
	"strings"
)

type Host struct {
	Name, User, Address, HostKey string
}

func (h Host) validate() error {
	if err := validName(h.Name); err != nil {
		return err
	}
	if h.User == "" || h.Address == "" || strings.ContainsAny(h.User+h.Address, " @/") {
		return fmt.Errorf("%w: user and address are required", ErrBadName)
	}
	return nil
}

func (s *Store) CreateHost(h Host, actor string) error {
	if err := h.validate(); err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO hosts(name,ssh_user,address) VALUES(?,?,?)`, h.Name, h.User, h.Address)
		return mapExists(err)
	}, actor, "host.create", h.Name, h.User+"@"+h.Address)
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT name,ssh_user,address,host_key FROM hosts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.Name, &h.User, &h.Address, &h.HostKey); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) DeleteHost(name, actor string) error {
	used, err := s.names(`SELECT p.name||'/'||e.name||'/'||t.name FROM targets t
	  JOIN hosts h ON h.id=t.host_id JOIN environments e ON e.id=t.env_id JOIN projects p ON p.id=e.project_id
	  WHERE h.name=? ORDER BY 1`, name)
	if err != nil {
		return err
	}
	if len(used) > 0 {
		return fmt.Errorf("host %s is %w by %s", name, ErrInUse, strings.Join(used, ", "))
	}
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`DELETE FROM hosts WHERE name=?`, name))
	}, actor, "host.delete", name, "")
}

func (s *Store) ForgetHostKey(name, actor string) error {
	return s.write(func(tx *sql.Tx) error {
		return mustAffect(tx.Exec(`UPDATE hosts SET host_key='' WHERE name=?`, name))
	}, actor, "host.unpin", name, "")
}
