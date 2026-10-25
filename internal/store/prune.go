package store

import "time"

func (s *Store) PruneAudit(before time.Time) (int64, error) {
	r, err := s.db.Exec(`DELETE FROM audit WHERE ts < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

func (s *Store) PruneHistory(keep int) (int64, error) {
	r, err := s.db.Exec(`DELETE FROM secret_versions WHERE id IN (
	  SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY env_id,key ORDER BY version DESC) AS n
	    FROM secret_versions) WHERE n > ?)`, keep)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
