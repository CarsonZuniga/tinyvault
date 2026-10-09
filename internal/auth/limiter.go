package auth

import (
	"sync"
	"time"
)

type entry struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
}

type limiter struct {
	mu              sync.Mutex
	m               map[string]*entry
	max             int
	window, lockout time.Duration
	now             func() time.Time
}

func newLimiter(max int, window, lockout time.Duration) *limiter {
	return &limiter{m: map[string]*entry{}, max: max, window: window, lockout: lockout, now: time.Now}
}

func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		return true, 0
	}
	if now := l.now(); now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.m) > 1000 {
		for k, e := range l.m {
			if now.After(e.lockedUntil) && now.Sub(e.first) > l.window {
				delete(l.m, k)
			}
		}
	}
	e := l.m[key]
	if e == nil || (now.After(e.lockedUntil) && now.Sub(e.first) > l.window) {
		e = &entry{first: now}
		l.m[key] = e
	}
	e.fails++
	if e.fails >= l.max {
		e.lockedUntil = now.Add(l.lockout)
		e.fails = 0
		e.first = now
	}
}

func (l *limiter) success(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
