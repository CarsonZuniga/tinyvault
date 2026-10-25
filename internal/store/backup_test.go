package store

import (
	"path/filepath"
	"testing"
)

func TestBackup(t *testing.T) {
	s, p := newStore(t)
	s.Set("media", "prod", "K", "v1", "admin")
	out := filepath.Join(t.TempDir(), "backup.db")
	if err := Backup(p, out, "admin"); err != nil {
		t.Fatal(err)
	}
	b, err := Open(out, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if v, _ := b.Get("media", "prod", "K", "admin"); v != "v1" {
		t.Fatalf("got %q", v)
	}
	if a, _ := s.ListAudit(1); a[0].Action != "db.backup" {
		t.Fatalf("audit %v", a)
	}
}
