package store

import (
	"database/sql"
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

func TestImportIsAtomic(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Import("media", "prod", map[string]string{"A": "1", "B": "2"}, "admin"); err != nil {
		t.Fatal(err)
	}
	m, err := s.getAll("media", "prod")
	if err != nil || m["A"] != "1" || m["B"] != "2" {
		t.Fatalf("%v %v", m, err)
	}
	before, _ := s.ListAudit(50)
	if err := s.Import("media", "prod", map[string]string{"C": "3", "bad key": "x"}, "admin"); err == nil {
		t.Fatal("invalid key must fail the whole batch")
	}
	if keys, _ := s.Keys("media", "prod"); len(keys) != 2 {
		t.Fatalf("partial import written: %v", keys)
	}
	if after, _ := s.ListAudit(50); len(after) != len(before) {
		t.Fatal("failed import was audited")
	}
}

func TestHostsAndTargets(t *testing.T) {
	s, p := newStore(t)
	s.CreateProject("music", "admin")
	s.CreateEnv("music", "prod", "admin")
	if err := s.CreateHost(Host{Name: "nas", User: "deploy", Address: "nas.lan"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(Host{Name: "bad", User: "", Address: "x"}, "admin"); !errors.Is(err, ErrBadName) {
		t.Fatal("host without user accepted")
	}
	nas := Host{Name: "nas"}
	if err := s.CreateTarget("media", "prod", Target{Name: "app", Host: nas, Path: "/srv/media/.env", Format: "dotenv"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTarget("music", "prod", Target{Name: "app", Host: nas, Path: "/srv/music/.env", Format: "json"}, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Target{
		{Name: "x", Host: nas, Path: "relative", Format: "dotenv"},
		{Name: "x", Host: nas, Path: "/a", Format: "toml"},
		{Name: "x", Host: Host{Name: "nope"}, Path: "/a", Format: "dotenv"},
	} {
		if err := s.CreateTarget("media", "prod", bad, "admin"); !errors.Is(err, ErrBadName) {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := s.CreateTarget("music", "prod", Target{Name: "dup", Host: nas, Path: "/srv/media/.env", Format: "dotenv"}, "admin"); !errors.Is(err, ErrInUse) {
		t.Fatalf("same host and path accepted: %v", err)
	}

	s.PinHostKey("media", "prod", "app", "ssh-ed25519 FIRST", "admin")
	if err := s.PinHostKey("music", "prod", "app", "ssh-ed25519 SECOND", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatal("pin must not overwrite an existing key")
	}
	if got, _ := s.GetTarget("music", "prod", "app"); got.Host.HostKey != "ssh-ed25519 FIRST" || got.Host.Address != "nas.lan" {
		t.Fatalf("pin not shared through host: %+v", got.Host)
	}
	if err := s.DeleteHost("nas", "admin"); !errors.Is(err, ErrInUse) || !strings.Contains(err.Error(), "media/prod/app, music/prod/app") {
		t.Fatalf("host in use deleted: %v", err)
	}
	s.DeleteProject("media", "admin")
	s.DeleteProject("music", "admin")
	if err := s.DeleteHost("nas", "admin"); err != nil {
		t.Fatal(err)
	}

	key := s.SSHKey()
	s.Close()
	s2, err := Open(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !key.Equal(s2.SSHKey()) {
		t.Fatal("ssh key not persisted")
	}
}

func TestMigrateReplacesOldTargets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.db")
	db, _ := sql.Open("sqlite", p)
	if _, err := db.Exec(`CREATE TABLE targets (id INTEGER PRIMARY KEY, ssh_user TEXT, host TEXT, host_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(migrations) {
		t.Fatalf("user_version %d", v)
	}
	if _, err := s.db.Exec(`SELECT host_id FROM targets`); err != nil {
		t.Fatalf("targets not recreated: %v", err)
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

func TestRotateKey(t *testing.T) {
	s, p := newStore(t)
	s.Set("media", "prod", "K", "v1", "admin")
	s.Set("media", "prod", "K", "v2", "admin")
	s.Delete("media", "prod", "K", "admin")
	sshKey := s.SSHKey()
	if err := s.RotateKey(testKey(2), "admin"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(p, testKey(1)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("old key: %v", err)
	}
	s2, err := Open(p, testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.SSHKey().Equal(sshKey) {
		t.Fatal("ssh key changed")
	}
	if err := s2.Rollback("media", "prod", "K", 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.Get("media", "prod", "K", "admin"); v != "v1" {
		t.Fatalf("got %q", v)
	}
}
