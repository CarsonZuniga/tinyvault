package store

import "database/sql"

func Backup(path, out, actor string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, out); err != nil {
		return err
	}
	return audit(db, actor, "db.backup", out, "")
}
