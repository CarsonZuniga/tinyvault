package store

import (
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/carsonzuniga/tinyvault/internal/crypto"
)

func (s *Store) RotateKey(newKey []byte, actor string) error {
	box, err := crypto.New(newKey)
	if err != nil {
		return err
	}
	type row struct {
		id  int64
		aad string
		ct  []byte
	}
	err = s.write(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT v.id,p.name,e.name,v.key,v.value FROM secret_versions v
		  JOIN environments e ON e.id=v.env_id JOIN projects p ON p.id=e.project_id
		  WHERE v.deleted=0`)
		if err != nil {
			return err
		}
		var all []row
		for rows.Next() {
			var r row
			var project, env, key string
			if err := rows.Scan(&r.id, &project, &env, &key, &r.ct); err != nil {
				rows.Close()
				return err
			}
			r.aad = aad(project, env, key)
			all = append(all, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range all {
			pt, err := s.box.Open(r.ct, r.aad)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", r.aad, err)
			}
			ct, err := box.Seal(pt, r.aad)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE secret_versions SET value=? WHERE id=?`, ct, r.id); err != nil {
				return err
			}
		}
		ct, err := box.Seal(s.sshKey.Seed(), sshKeyAAD)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE meta SET v=? WHERE k='ssh_key'`, base64.StdEncoding.EncodeToString(ct)); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE meta SET v=? WHERE k='key_fp'`, crypto.Fingerprint(newKey))
		return err
	}, actor, "master_key.rotate", "", "")
	if err != nil {
		return err
	}
	s.box = box
	return nil
}
