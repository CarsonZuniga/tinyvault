package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func init() {
	argonMem, argonTime, argonThreads = 64, 1, 1
}

const pw = "correct horse battery"

func TestPassword(t *testing.T) {
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword(pw, h); !ok {
		t.Fatal("correct password rejected")
	}
	if ok, _ := VerifyPassword("wrong horse battery", h); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword(pw)
	if h == h2 {
		t.Fatal("salt must differ between hashes")
	}
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal("weak password accepted")
	}
	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=0,t=1,p=1$AA$AA", "$bcrypt$v=19$m=1,t=1,p=1$AA$AA"} {
		if _, err := VerifyPassword(pw, bad); err == nil {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestSessionExpiry(t *testing.T) {
	now := time.Now()
	s := newSessions(10*time.Minute, time.Hour)
	s.now = func() time.Time { return now }
	tok := s.create()
	if _, ok := s.get(tok); !ok {
		t.Fatal("fresh session rejected")
	}
	now = now.Add(9 * time.Minute)
	if _, ok := s.get(tok); !ok {
		t.Fatal("session within idle window rejected")
	}
	now = now.Add(11 * time.Minute)
	if _, ok := s.get(tok); ok {
		t.Fatal("idle session accepted")
	}
	tok = s.create()
	for i := 0; i < 7; i++ {
		now = now.Add(9 * time.Minute)
		s.get(tok)
	}
	if _, ok := s.get(tok); ok {
		t.Fatal("session past max age accepted despite activity")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Now()
	l := newLimiter(3, time.Minute, time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatal("locked too early")
		}
		l.fail("a")
	}
	if ok, wait := l.allow("a"); ok || wait <= 0 {
		t.Fatal("not locked after max failures")
	}
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("other key affected")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("lock did not expire")
	}
}

func newAuth(t *testing.T, cfg Config) (*Auth, http.Handler) {
	t.Helper()
	h, _ := HashPassword(pw)
	cfg.PasswordHash = h
	a := New(cfg)
	prot := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(CSRFToken(r)))
	}))
	return a, prot
}

func login(t *testing.T, a *Auth, password string) (*http.Cookie, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	err := a.Login(rec, httptest.NewRequest("POST", "/login", nil), password)
	if err != nil {
		return nil, err
	}
	return rec.Result().Cookies()[0], nil
}

func do(h http.Handler, method string, c *http.Cookie, hdr map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/x", strings.NewReader(body))
	if c != nil {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestFlowAndCSRF(t *testing.T) {
	a, h := newAuth(t, Config{})
	if rec := do(h, "GET", nil, nil, ""); rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Fatalf("anon GET: %d", rec.Code)
	}
	if rec := do(h, "POST", nil, nil, ""); rec.Code != 401 {
		t.Fatalf("anon POST: %d", rec.Code)
	}
	c, err := login(t, a, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie flags missing")
	}
	rec := do(h, "GET", c, nil, "")
	csrf := rec.Body.String()
	if rec.Code != 200 || len(csrf) < 20 {
		t.Fatalf("authed GET: %d %q", rec.Code, csrf)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	if rec := do(h, "POST", c, nil, ""); rec.Code != 403 {
		t.Fatalf("POST without csrf: %d", rec.Code)
	}
	if rec := do(h, "POST", c, map[string]string{"X-CSRF-Token": "nope"}, ""); rec.Code != 403 {
		t.Fatalf("POST wrong csrf: %d", rec.Code)
	}
	if rec := do(h, "POST", c, map[string]string{"X-CSRF-Token": csrf}, ""); rec.Code != 200 {
		t.Fatalf("POST header csrf: %d", rec.Code)
	}
	form := url.Values{"csrf": {csrf}}.Encode()
	if rec := do(h, "POST", c, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form); rec.Code != 200 {
		t.Fatalf("POST form csrf: %d", rec.Code)
	}
	lo := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/logout", nil)
	r.AddCookie(c)
	a.Logout(lo, r)
	if rec := do(h, "GET", c, nil, ""); rec.Code != 303 {
		t.Fatalf("session usable after logout: %d", rec.Code)
	}
}

func TestLoginSessionIsFresh(t *testing.T) {
	a, _ := newAuth(t, Config{})
	c1, _ := login(t, a, pw)
	c2, _ := login(t, a, pw)
	if c1.Value == c2.Value {
		t.Fatal("token reused across logins")
	}
}

func TestLockout(t *testing.T) {
	a, _ := newAuth(t, Config{})
	for i := 0; i < 5; i++ {
		if _, err := login(t, a, "wrong horse battery"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := login(t, a, pw)
	var le *LockedError
	if !errors.As(err, &le) || le.RetryAfter <= 0 {
		t.Fatalf("want LockedError even with correct password, got %v", err)
	}
}

func TestSecureCookieAndPasswordChange(t *testing.T) {
	a, h := newAuth(t, Config{SecureCookies: true})
	c, _ := login(t, a, pw)
	if c.Name != "__Host-tv_session" || !c.Secure {
		t.Fatalf("secure cookie: %+v", c)
	}
	newHash, _ := HashPassword("another long password")
	a.SetPasswordHash(newHash)
	if rec := do(h, "GET", c, nil, ""); rec.Code != 303 {
		t.Fatal("sessions survived password change")
	}
	if _, err := login(t, a, pw); err == nil {
		t.Fatal("old password still works")
	}
}

func TestNotConfigured(t *testing.T) {
	a := New(Config{})
	if _, err := login(t, a, pw); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("got %v", err)
	}
}

func TestHeaderIP(t *testing.T) {
	f := HeaderIP("CF-Connecting-IP")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:4000"
	if got := f(r); got != "10.0.0.5" {
		t.Fatalf("fallback: %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "203.0.113.9, 10.1.1.1")
	if got := f(r); got != "203.0.113.9" {
		t.Fatalf("header: %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "not-an-ip")
	if got := f(r); got != "10.0.0.5" {
		t.Fatalf("garbage header: %s", got)
	}
}
