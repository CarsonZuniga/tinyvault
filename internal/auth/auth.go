package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	idleTimeout = 30 * time.Minute
	maxAge      = 12 * time.Hour
	loginPath   = "/login"
)

var ErrInvalidCredentials = errors.New("invalid password")

type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("too many attempts, retry in %s", e.RetryAfter.Round(time.Second))
}

type Config struct {
	PasswordHash  string
	SecureCookies bool
	ClientIP      func(*http.Request) string
}

type Auth struct {
	cfg    Config
	sess   *sessions
	perIP  *limiter
	global *limiter
}

type ctxKey struct{}

func New(cfg Config) *Auth {
	if cfg.ClientIP == nil {
		cfg.ClientIP = remoteIP
	}
	return &Auth{
		cfg:    cfg,
		sess:   newSessions(idleTimeout, maxAge),
		perIP:  newLimiter(5, 15*time.Minute, 15*time.Minute),
		global: newLimiter(50, 15*time.Minute, 5*time.Minute),
	}
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request, password string) error {
	ip := a.cfg.ClientIP(r)
	for _, l := range []struct {
		lim *limiter
		key string
	}{{a.perIP, ip}, {a.global, "*"}} {
		if ok, wait := l.lim.allow(l.key); !ok {
			return &LockedError{RetryAfter: wait}
		}
	}
	ok, err := VerifyPassword(password, a.cfg.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		a.perIP.fail(ip)
		a.global.fail("*")
		return ErrInvalidCredentials
	}
	a.perIP.success(ip)
	if c, err := r.Cookie(a.cookieName()); err == nil {
		a.sess.delete(c.Value)
	}
	http.SetCookie(w, a.cookie(a.sess.create(), int(maxAge.Seconds())))
	return nil
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cookieName()); err == nil {
		a.sess.delete(c.Value)
	}
	http.SetCookie(w, a.cookie("", -1))
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var s Session
		ok := false
		if c, err := r.Cookie(a.cookieName()); err == nil {
			s, ok = a.sess.get(c.Value)
		}
		if !ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, loginPath, http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !safeMethod(r.Method) && !validCSRF(r, s.CSRF) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	})
}

func CSRFToken(r *http.Request) string {
	s, _ := r.Context().Value(ctxKey{}).(Session)
	return s.CSRF
}

func HeaderIP(name string) func(*http.Request) string {
	return func(r *http.Request) string {
		v, _, _ := strings.Cut(r.Header.Get(name), ",")
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip.String()
		}
		return remoteIP(r)
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Auth) cookieName() string {
	if a.cfg.SecureCookies {
		return "__Host-tv_session"
	}
	return "tv_session"
}

func (a *Auth) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: a.cookieName(), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: a.cfg.SecureCookies, SameSite: http.SameSiteStrictMode,
	}
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func validCSRF(r *http.Request, want string) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.PostFormValue("csrf")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
