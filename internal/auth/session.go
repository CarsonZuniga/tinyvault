package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct{ CSRF string }

type record struct {
	csrf          string
	created, seen time.Time
}

type sessions struct {
	mu        sync.Mutex
	m         map[[32]byte]record
	idle, max time.Duration
	now       func() time.Time
}

func newSessions(idle, max time.Duration) *sessions {
	return &sessions{m: map[[32]byte]record{}, idle: idle, max: max, now: time.Now}
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func digest(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (s *sessions) expired(r record, now time.Time) bool {
	return now.Sub(r.seen) > s.idle || now.Sub(r.created) > s.max
}

func (s *sessions) create() string {
	token := randToken()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, r := range s.m {
		if s.expired(r, now) {
			delete(s.m, k)
		}
	}
	s.m[digest(token)] = record{csrf: randToken(), created: now, seen: now}
	return token
}

func (s *sessions) get(token string) (Session, bool) {
	key := digest(token)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[key]
	if !ok {
		return Session{}, false
	}
	if s.expired(r, now) {
		delete(s.m, key)
		return Session{}, false
	}
	r.seen = now
	s.m[key] = r
	return Session{CSRF: r.csrf}, true
}

func (s *sessions) delete(token string) {
	s.mu.Lock()
	delete(s.m, digest(token))
	s.mu.Unlock()
}
