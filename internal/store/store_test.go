package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v.db")
	s, err := Open(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.CreateProject("media", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEnv("media", "prod", "admin"); err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestSetGetAndVersions(t *testing.T) {
	s, _ := newStore(t)
	s.Set("media", "prod", "DB_PASS", "one", "admin")
	s.Set("media", "prod", "DB_PASS", "two", "admin")
	if v, _ := s.Get("media", "prod", "DB_PASS", "admin"); v != "two" {
		t.Fatalf("got %q", v)
	}
	h, _ := s.History("media", "prod", "DB_PASS")
	if len(h) != 2 || h[0].Version != 2 {
		t.Fatalf("history %v", h)
	}
	if err := s.Rollback("media", "prod", "DB_PASS", 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("media", "prod", "DB_PASS", "admin"); v != "one" {
		t.Fatalf("rollback got %q", v)
	}
	if h, _ = s.History("media", "prod", "DB_PASS"); len(h) != 3 {
		t.Fatalf("rollback must add a version, got %d", len(h))
	}
}

func TestDeleteTombstoneAndRestore(t *testing.T) {
	s, _ := newStore(t)
	s.Set("media", "prod", "K", "v1", "admin")
	if err := s.Delete("media", "prod", "K", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("media", "prod", "K", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted key must be gone")
	}
	if keys, _ := s.Keys("media", "prod"); len(keys) != 0 {
		t.Fatalf("keys %v", keys)
	}
	if err := s.Delete("media", "prod", "K", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete must be NotFound")
	}
	if err := s.Rollback("media", "prod", "K", 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("media", "prod", "K", "admin"); v != "v1" {
		t.Fatal("restore failed")
	}
}

func TestEncryptedAtRestAndWrongKey(t *testing.T) {
	s, p := newStore(t)
	s.Set("media", "prod", "TOKEN", "super-secret-plaintext", "admin")
	var raw []byte
	s.db.QueryRow(`SELECT value FROM secret_versions`).Scan(&raw)
	if strings.Contains(string(raw), "super-secret") {
		t.Fatal("plaintext stored in DB")
	}
	s.Close()
	if _, err := Open(p, testKey(2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("want ErrWrongKey, got %v", err)
	}
}

func TestSwappedCiphertextRejected(t *testing.T) {
	s, _ := newStore(t)
	s.Set("media", "prod", "A", "alpha", "admin")
	s.Set("media", "prod", "B", "beta", "admin")
	s.db.Exec(`UPDATE secret_versions SET value=(SELECT value FROM secret_versions WHERE key='A') WHERE key='B'`)
	if _, err := s.Get("media", "prod", "B", "admin"); err == nil {
		t.Fatal("swapped ciphertext must fail to decrypt")
	}
}

func TestImportGetAllAndAudit(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Import("media", "prod", map[string]string{"A": "1", "B": "2"}, "admin"); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetAll("media", "prod", "admin")
	if err != nil || m["A"] != "1" || m["B"] != "2" {
		t.Fatalf("%v %v", m, err)
	}
	if err := s.Import("media", "prod", map[string]string{"bad key": "x"}, "admin"); err == nil {
		t.Fatal("invalid key must fail the whole batch")
	}
	log, _ := s.ListAudit(50)
	for _, e := range log {
		if strings.Contains(e.Detail+e.Target, "1") && e.Action == "secret.export" && e.Detail != "2 keys" {
			t.Fatal("audit leaked something unexpected")
		}
	}
	if log[0].Action != "secret.export" {
		t.Fatalf("latest audit %q", log[0].Action)
	}
}

func TestValidationAndCascade(t *testing.T) {
	s, _ := newStore(t)
	if err := s.CreateProject("Bad Name", "a"); !errors.Is(err, ErrBadName) {
		t.Fatal("bad name accepted")
	}
	if err := s.CreateProject("media", "a"); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	s.Set("media", "prod", "K", "v", "admin")
	if err := s.DeleteProject("media", "admin"); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM secret_versions`).Scan(&n)
	if n != 0 {
		t.Fatal("cascade delete failed")
	}
}
