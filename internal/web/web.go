package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/carsonzuniga/tinyvault/internal/auth"
	"github.com/carsonzuniga/tinyvault/internal/formats"
	"github.com/carsonzuniga/tinyvault/internal/store"
)

const actor = "admin"

//go:embed templates static
var assets embed.FS

type Server struct {
	st  *store.Store
	au  *auth.Auth
	tpl *template.Template
}

func New(st *store.Store, au *auth.Auth) *Server {
	return &Server{st: st, au: au, tpl: template.Must(template.ParseFS(assets, "templates/*.html"))}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)

	prot := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.au.Require(h)) }
	prot("POST /logout", s.logout)
	prot("GET /{$}", s.projects)
	prot("POST /projects", s.createProject)
	prot("GET /p/{project}", s.project)
	prot("POST /p/{project}/delete", s.deleteProject)
	prot("POST /p/{project}/envs", s.createEnv)
	prot("GET /p/{project}/{env}", s.env)
	prot("POST /p/{project}/{env}/delete", s.deleteEnv)
	prot("POST /p/{project}/{env}/keys", s.setKey)
	prot("POST /p/{project}/{env}/keys/{key}/delete", s.deleteKey)
	prot("POST /p/{project}/{env}/keys/{key}/reveal", s.reveal)
	prot("POST /p/{project}/{env}/import", s.importKeys)
	prot("GET /p/{project}/{env}/export", s.export)
	return secure(mux)
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

type page struct {
	Title, Err, Notice, CSRF string
	Authed                   bool
}

type loginPage struct{ page }
type messagePage struct{ page }
type projectsPage struct {
	page
	Projects []string
}
type projectPage struct {
	page
	Project string
	Envs    []string
}
type revealed struct{ Key, Value string }
type envPage struct {
	page
	Project, Env string
	Keys         []string
	Revealed     *revealed
}

var notices = map[string]string{"saved": "Key saved.", "deleted": "Key deleted."}

func (s *Server) pg(r *http.Request, title, errMsg string) page {
	tok := auth.CSRFToken(r)
	p := page{Title: title, Err: errMsg, CSRF: tok, Authed: tok != ""}
	q := r.URL.Query()
	if q.Get("n") == "imported" {
		if c, err := strconv.Atoi(q.Get("c")); err == nil && c >= 0 {
			p.Notice = fmt.Sprintf("Imported %d keys.", c)
		}
	} else {
		p.Notice = notices[q.Get("n")]
	}
	return p
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func problem(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "Not found."
	case errors.Is(err, store.ErrExists):
		return http.StatusConflict, "That name already exists."
	case errors.Is(err, store.ErrBadName):
		return http.StatusBadRequest, err.Error()
	}
	log.Printf("internal error: %v", err)
	return http.StatusInternalServerError, "Something went wrong. Check the server log."
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, msg := problem(err)
	s.render(w, status, "message", messagePage{s.pg(r, "Error", msg)})
}

func envURL(project, env string) string {
	return "/p/" + url.PathEscape(project) + "/" + url.PathEscape(env)
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", loginPage{page{Title: "Log in"}})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	err := s.au.Login(w, r, r.PostFormValue("password"))
	var locked *auth.LockedError
	switch {
	case err == nil:
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", strconv.Itoa(int(locked.RetryAfter.Seconds())+1))
		s.render(w, http.StatusTooManyRequests, "login", loginPage{page{Title: "Log in", Err: locked.Error()}})
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.render(w, http.StatusUnauthorized, "login", loginPage{page{Title: "Log in", Err: "Wrong password."}})
	default:
		log.Printf("login: %v", err)
		s.render(w, http.StatusInternalServerError, "login", loginPage{page{Title: "Log in", Err: "Login is unavailable. Check the server log."}})
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.au.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	s.projectsView(w, r, http.StatusOK, "")
}

func (s *Server) projectsView(w http.ResponseWriter, r *http.Request, status int, msg string) {
	list, err := s.st.ListProjects()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, status, "projects", projectsPage{page: s.pg(r, "Projects", msg), Projects: list})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.st.CreateProject(name, actor); err != nil {
		status, msg := problem(err)
		s.projectsView(w, r, status, msg)
		return
	}
	http.Redirect(w, r, "/p/"+url.PathEscape(name), http.StatusSeeOther)
}

func (s *Server) project(w http.ResponseWriter, r *http.Request) {
	s.projectView(w, r, http.StatusOK, "")
}

func (s *Server) projectView(w http.ResponseWriter, r *http.Request, status int, msg string) {
	project := r.PathValue("project")
	envs, err := s.st.ListEnvs(project)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, status, "project", projectPage{page: s.pg(r, project, msg), Project: project, Envs: envs})
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	if r.PostFormValue("confirm") != project {
		s.projectView(w, r, http.StatusBadRequest, "Type the project name to confirm deletion.")
		return
	}
	if err := s.st.DeleteProject(project, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) createEnv(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.st.CreateEnv(project, name, actor); err != nil {
		status, msg := problem(err)
		if status == http.StatusNotFound {
			s.fail(w, r, err)
			return
		}
		s.projectView(w, r, status, msg)
		return
	}
	http.Redirect(w, r, envURL(project, name), http.StatusSeeOther)
}

func (s *Server) env(w http.ResponseWriter, r *http.Request) { s.envView(w, r, http.StatusOK, "", nil) }

func (s *Server) envView(w http.ResponseWriter, r *http.Request, status int, msg string, rev *revealed) {
	project, env := r.PathValue("project"), r.PathValue("env")
	keys, err := s.st.Keys(project, env)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, status, "env", envPage{page: s.pg(r, project+"/"+env, msg), Project: project, Env: env, Keys: keys, Revealed: rev})
}

func (s *Server) deleteEnv(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	if r.PostFormValue("confirm") != env {
		s.envView(w, r, http.StatusBadRequest, "Type the environment name to confirm deletion.", nil)
		return
	}
	if err := s.st.DeleteEnv(project, env, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/p/"+url.PathEscape(project), http.StatusSeeOther)
}

func (s *Server) setKey(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	key := strings.TrimSpace(r.PostFormValue("key"))
	if err := s.st.Set(project, env, key, r.PostFormValue("value"), actor); err != nil {
		status, msg := problem(err)
		if status == http.StatusNotFound {
			s.fail(w, r, err)
			return
		}
		s.envView(w, r, status, msg, nil)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=saved", http.StatusSeeOther)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	if err := s.st.Delete(project, env, r.PathValue("key"), actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=deleted", http.StatusSeeOther)
}

func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	val, err := s.st.Get(r.PathValue("project"), r.PathValue("env"), key, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.envView(w, r, http.StatusOK, "", &revealed{Key: key, Value: val})
}

func parseAny(in string) (map[string]string, error) {
	t := strings.TrimSpace(in)
	switch {
	case t == "":
		return nil, errors.New("nothing to import")
	case strings.HasPrefix(t, "{"):
		return formats.ParseJSON(t)
	case strings.Contains(t, "apiVersion:"):
		return formats.ParseK8sSecret(t)
	}
	return formats.ParseDotenv(t)
}

func (s *Server) importKeys(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	kv, err := parseAny(r.PostFormValue("data"))
	if err == nil && len(kv) == 0 {
		err = errors.New("no keys found")
	}
	if err != nil {
		s.envView(w, r, http.StatusBadRequest, "Could not parse input: "+err.Error(), nil)
		return
	}
	if err := s.st.Import(project, env, kv, actor); err != nil {
		status, msg := problem(err)
		if status == http.StatusNotFound {
			s.fail(w, r, err)
			return
		}
		s.envView(w, r, status, msg, nil)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s?n=imported&c=%d", envURL(project, env), len(kv)), http.StatusSeeOther)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	m, err := s.st.GetAll(project, env, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if r.URL.Query().Get("resolve") == "1" {
		if m, err = formats.Resolve(m); err != nil {
			s.envView(w, r, http.StatusBadRequest, "Cannot resolve references: "+err.Error(), nil)
			return
		}
	}
	var body, ext string
	switch r.URL.Query().Get("format") {
	case "json":
		body, ext = formats.ExportJSON(m), "json"
	case "shell":
		body, ext = formats.ExportShell(m), "sh"
	case "k8s":
		body, ext = formats.ExportK8sSecret(strings.ReplaceAll(project+"-"+env, "_", "-"), "default", m), "yaml"
	default:
		body, ext = formats.ExportDotenv(m), "env"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, project, env, ext))
	_, _ = w.Write([]byte(body))
}
