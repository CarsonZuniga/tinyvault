package store

import (
	"database/sql"
	"time"
)

func (s *Store) CloneEnv(project, env, toProject, toEnv, actor string) error {
	if err := validName(toEnv); err != nil {
		return err
	}
	m, err := s.getAll(project, env)
	if err != nil {
		return err
	}
	pid, err := s.projectID(toProject)
	if err != nil {
		return err
	}
	return s.write(func(tx *sql.Tx) error {
		r, err := tx.Exec(`INSERT INTO environments(project_id,name,created_at) VALUES(?,?,?)`,
			pid, toEnv, time.Now().Unix())
		if err != nil {
			return mapExists(err)
		}
		eid, err := r.LastInsertId()
		if err != nil {
			return err
		}
		for k, v := range m {
			if err := s.insertVersion(tx, eid, toProject, toEnv, k, v, actor); err != nil {
				return err
			}
		}
		return nil
	}, actor, "env.clone", toProject+"/"+toEnv, "from "+project+"/"+env)
}
