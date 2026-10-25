package store

import (
	"errors"
	"testing"
)

func TestCloneEnv(t *testing.T) {
	s, _ := newStore(t)
	s.Set("media", "prod", "A", "old", "admin")
	s.Set("media", "prod", "A", "new", "admin")
	s.Set("media", "prod", "GONE", "x", "admin")
	s.Delete("media", "prod", "GONE", "admin")
	s.CreateProject("other", "admin")
	if err := s.CloneEnv("media", "prod", "other", "staging", "admin"); err != nil {
		t.Fatal(err)
	}
	m, err := s.getAll("other", "staging")
	if err != nil || len(m) != 1 || m["A"] != "new" {
		t.Fatalf("%v %v", m, err)
	}
	if h, _ := s.History("other", "staging", "A"); len(h) != 1 || h[0].Version != 1 {
		t.Fatalf("history %v", h)
	}
	if err := s.CloneEnv("media", "prod", "other", "staging", "admin"); !errors.Is(err, ErrExists) {
		t.Fatalf("clone onto existing env: %v", err)
	}
}
