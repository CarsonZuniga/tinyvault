package web

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/carsonzuniga/tinyvault/internal/auth"
	"github.com/carsonzuniga/tinyvault/internal/store"
)

const adminPW = "correct horse battery"

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

type env struct {
	t   *testing.T
	ts  *httptest.Server
	c   *http.Client
	csr string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, err := auth.HashPassword(adminPW)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(st, auth.New(auth.Config{PasswordHash: hash})).Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return &env{t: t, ts: ts, c: &http.Client{Jar: jar}}
}

func (e *env) do(req *http.Request) (int, string, http.Header) {
	e.t.Helper()
	resp, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (e *env) get(path string) (int, string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	return e.do(req)
}

func (e *env) post(path string, form url.Values) (int, string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(req)
}

func (e *env) postCSRF(path string, form url.Values) (int, string, http.Header) {
	e.t.Helper()
	form.Set("csrf", e.csr)
	return e.post(path, form)
}

func (e *env) login() {
	e.t.Helper()
	code, body, _ := e.post("/login", url.Values{"password": {adminPW}})
	m := csrfRe.FindStringSubmatch(body)
	if code != 200 || m == nil {
		e.t.Fatalf("login failed: %d", code)
	}
	e.csr = m[1]
}

func (e *env) seed() {
	e.t.Helper()
	e.login()
	if code, _, _ := e.postCSRF("/projects", url.Values{"name": {"media"}}); code != 200 {
		e.t.Fatalf("create project: %d", code)
	}
	if code, _, _ := e.postCSRF("/p/media/envs", url.Values{"name": {"prod"}}); code != 200 {
		e.t.Fatalf("create env: %d", code)
	}
}

func TestAuthRequiredAndHeaders(t *testing.T) {
	e := newEnv(t)
	code, body, hdr := e.get("/")
	if code != 200 || !strings.Contains(body, "Log in") {
		t.Fatalf("anon / should land on login, got %d", code)
	}
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'none'") ||
		hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", hdr)
	}
	if code, _, _ := e.post("/projects", url.Values{"name": {"x"}}); code != 401 {
		t.Fatalf("anon POST: %d", code)
	}
	if code, _, _ := e.post("/login", url.Values{"password": {"wrong horse battery"}}); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
}

func TestCSRFRequired(t *testing.T) {
	e := newEnv(t)
	e.login()
	if code, _, _ := e.post("/projects", url.Values{"name": {"nocsrf"}}); code != 403 {
		t.Fatalf("POST without csrf: %d", code)
	}
	if code, _, _ := e.postCSRF("/logout", url.Values{}); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if _, body, _ := e.get("/"); !strings.Contains(body, "Log in") {
		t.Fatal("still logged in after logout")
	}
}

func TestFullFlowAndSecretsStayHidden(t *testing.T) {
	e := newEnv(t)
	e.seed()
	code, body, _ := e.postCSRF("/p/media/prod/import", url.Values{"data": {"DB_HOST=db\nSECRET=hunter2hunter2\n"}})
	if code != 200 || !strings.Contains(body, "Imported 2 keys.") {
		t.Fatalf("import: %d", code)
	}
	if !strings.Contains(body, "SECRET") || strings.Contains(body, "hunter2hunter2") {
		t.Fatal("key list must show names but never values")
	}
	_, body, _ = e.postCSRF("/p/media/prod/keys/SECRET/reveal", url.Values{})
	if !strings.Contains(body, "hunter2hunter2") {
		t.Fatal("reveal did not show the value")
	}
	if _, body, _ = e.get("/p/media/prod"); strings.Contains(body, "hunter2hunter2") {
		t.Fatal("value persisted in page after reveal")
	}
	code, body, hdr := e.get("/p/media/prod/export?format=dotenv")
	if code != 200 || !strings.Contains(body, "SECRET=hunter2hunter2") ||
		!strings.Contains(hdr.Get("Content-Disposition"), "media-prod.env") || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("export: %d %v", code, hdr)
	}
	if _, body, _ = e.get("/p/media/prod/export?format=json"); !strings.Contains(body, `"DB_HOST": "db"`) {
		t.Fatalf("json export: %s", body)
	}
	if _, body, _ = e.get("/p/media/prod/export?format=k8s"); !strings.Contains(body, "name: media-prod") {
		t.Fatalf("k8s export: %s", body)
	}
	code, body, _ = e.postCSRF("/p/media/prod/keys/SECRET/delete", url.Values{})
	if code != 200 || strings.Contains(body, "<code>SECRET</code>") {
		t.Fatal("delete failed")
	}
}

func TestSetKeyAndImportFormats(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if code, body, _ := e.postCSRF("/p/media/prod/keys", url.Values{"key": {"TOKEN"}, "value": {"abc"}}); code != 200 || !strings.Contains(body, "Key saved.") {
		t.Fatalf("set key: %d", code)
	}
	if code, _, _ := e.postCSRF("/p/media/prod/keys", url.Values{"key": {"bad key"}, "value": {"x"}}); code != 400 {
		t.Fatalf("invalid key accepted: %d", code)
	}
	if code, body, _ := e.postCSRF("/p/media/prod/import", url.Values{"data": {`{"A":"1","B":"2","C":"3"}`}}); code != 200 || !strings.Contains(body, "Imported 3 keys.") {
		t.Fatalf("json import: %d", code)
	}
	k8s := "apiVersion: v1\nkind: Secret\ndata:\n  K8S_KEY: aGVsbG8=\n"
	if code, body, _ := e.postCSRF("/p/media/prod/import", url.Values{"data": {k8s}}); code != 200 || !strings.Contains(body, "Imported 1 keys.") {
		t.Fatalf("k8s import: %d", code)
	}
	if code, _, _ := e.postCSRF("/p/media/prod/import", url.Values{"data": {"not a valid line"}}); code != 400 {
		t.Fatalf("garbage import accepted: %d", code)
	}
}

func TestResolveRefsOnExport(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.postCSRF("/p/media/prod/import", url.Values{"data": {"HOST=db\nURL=pg://${HOST}:5432\n"}})
	if _, body, _ := e.get("/p/media/prod/export?resolve=1"); !strings.Contains(body, "URL=pg://db:5432") {
		t.Fatalf("resolve: %s", body)
	}
	e.postCSRF("/p/media/prod/import", url.Values{"data": {"A=${B}\nB=${A}\n"}})
	if code, _, _ := e.get("/p/media/prod/export?resolve=1"); code != 400 {
		t.Fatalf("cycle should be a 400, got %d", code)
	}
}

func TestEscapingOfRevealedValue(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.postCSRF("/p/media/prod/import", url.Values{"data": {`{"EVIL":"</textarea><script>alert(1)</script>"}`}})
	_, body, _ := e.postCSRF("/p/media/prod/keys/EVIL/reveal", url.Values{})
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("revealed value not escaped")
	}
}

func TestDeletesNeedConfirmation(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if code, _, _ := e.postCSRF("/p/media/delete", url.Values{"confirm": {"nope"}}); code != 400 {
		t.Fatalf("project delete without confirm: %d", code)
	}
	if _, body, _ := e.get("/"); !strings.Contains(body, "media") {
		t.Fatal("project vanished")
	}
	if code, _, _ := e.postCSRF("/p/media/prod/delete", url.Values{"confirm": {"prod"}}); code != 200 {
		t.Fatalf("env delete: %d", code)
	}
	if code, _, _ := e.postCSRF("/p/media/delete", url.Values{"confirm": {"media"}}); code != 200 {
		t.Fatalf("project delete: %d", code)
	}
	if code, _, _ := e.get("/p/media"); code != 404 {
		t.Fatalf("deleted project still reachable: %d", code)
	}
}

func TestDuplicatesAndBadNames(t *testing.T) {
	e := newEnv(t)
	e.seed()
	if code, body, _ := e.postCSRF("/projects", url.Values{"name": {"media"}}); code != 409 || !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate project: %d", code)
	}
	if code, _, _ := e.postCSRF("/projects", url.Values{"name": {"Bad Name"}}); code != 400 {
		t.Fatalf("bad name: %d", code)
	}
	if code, _, _ := e.get("/p/does-not-exist"); code != 404 {
		t.Fatalf("missing project: %d", code)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.post("/login", url.Values{"password": {"wrong horse battery"}})
	}
	code, _, hdr := e.post("/login", url.Values{"password": {adminPW}})
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("lockout: %d %v", code, hdr)
	}
}

func TestHistoryRollbackAndAudit(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.postCSRF("/p/media/prod/keys", url.Values{"key": {"K"}, "value": {"one"}})
	e.postCSRF("/p/media/prod/keys", url.Values{"key": {"K"}, "value": {"two"}})
	if code, body, _ := e.get("/p/media/prod/keys/K"); code != 200 || !strings.Contains(body, `name="version" value="1"`) {
		t.Fatalf("history: %d", code)
	}
	if code, _, _ := e.postCSRF("/p/media/prod/keys/K/rollback", url.Values{"version": {"1"}}); code != 200 {
		t.Fatalf("rollback: %d", code)
	}
	if _, body, _ := e.postCSRF("/p/media/prod/keys/K/reveal", url.Values{}); !strings.Contains(body, ">one</textarea>") {
		t.Fatal("rollback did not restore v1")
	}
	if _, body, _ := e.get("/audit"); !strings.Contains(body, "secret.rollback") || strings.Contains(body, ">one<") {
		t.Fatal("audit page missing entry or leaking values")
	}
}

func TestCreateTarget(t *testing.T) {
	e := newEnv(t)
	e.seed()
	form := url.Values{"name": {"nas"}, "user": {"deploy"}, "host": {"nas.lan"}, "path": {"/srv/app/.env"}, "format": {"dotenv"}}
	code, body, _ := e.postCSRF("/p/media/prod/targets", form)
	if code != 200 || !strings.Contains(body, "deploy@nas.lan:/srv/app/.env") || !strings.Contains(body, "ssh-ed25519 ") {
		t.Fatalf("create target: %d", code)
	}
	form.Set("name", "other")
	form.Set("path", "relative.env")
	if code, _, _ := e.postCSRF("/p/media/prod/targets", form); code != 400 {
		t.Fatalf("relative path accepted: %d", code)
	}
}
