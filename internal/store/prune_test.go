package store

import (
	"errors"
	"testing"
	"time"
)

func TestPrune(t *testing.T) {
	s, _ := newStore(t)
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		s.Set("media", "prod", "K", v, "admin")
	}
	s.Delete("media", "prod", "K", "admin")
	s.Set("media", "prod", "OTHER", "x", "admin")
	if n, err := s.PruneHistory(2); err != nil || n != 3 {
		t.Fatalf("pruned %d versions, err %v", n, err)
	}
	h, _ := s.History("media", "prod", "K")
	if len(h) != 2 || h[0].Version != 5 || !h[0].Deleted {
		t.Fatalf("history %v", h)
	}
	if err := s.Rollback("media", "prod", "K", 1, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback to pruned version: %v", err)
	}
	if err := s.Rollback("media", "prod", "K", 4, "admin"); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.History("media", "prod", "K"); h[0].Version != 6 {
		t.Fatalf("version after prune %d", h[0].Version)
	}

	s.db.Exec(`UPDATE audit SET ts=? WHERE action='project.create'`, time.Now().AddDate(0, 0, -40).Unix())
	before, _ := s.ListAudit(50)
	if n, err := s.PruneAudit(time.Now().AddDate(0, 0, -30)); err != nil || n != 1 {
		t.Fatalf("pruned %d audit entries, err %v", n, err)
	}
	if after, _ := s.ListAudit(50); len(after) != len(before)-1 {
		t.Fatalf("audit %d -> %d", len(before), len(after))
	}
}
