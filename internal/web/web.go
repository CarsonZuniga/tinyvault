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
	"github.com/carsonzuniga/tinyvault/internal/push"
	"github.com/carsonzuniga/tinyvault/internal/store"
)

const actor = "admin"

//go:embed templates static
var assets embed.FS

type Server struct {
	st  *store.Store
	au  *auth.Auth
	pu  *push.Pusher
	tpl *template.Template
}

func New(st *store.Store, au *auth.Auth, pu *push.Pusher) *Server {
	return &Server{st: st, au: au, pu: pu, tpl: template.Must(template.ParseFS(assets, "templates/*.html"))}
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
	prot("GET /audit", s.audit)
	prot("GET /hosts", s.hosts)
	prot("POST /hosts", s.createHost)
	prot("POST /hosts/{host}/forget-key", s.forgetHostKey)
	prot("POST /hosts/{host}/delete", s.deleteHost)
	prot("POST /projects", s.createProject)
	prot("GET /p/{project}", s.project)
	prot("POST /p/{project}/delete", s.deleteProject)
	prot("POST /p/{project}/envs", s.createEnv)
	prot("GET /p/{project}/{env}", s.env)
	prot("POST /p/{project}/{env}/delete", s.deleteEnv)
	prot("POST /p/{project}/{env}/clone", s.cloneEnv)
	prot("POST /p/{project}/{env}/keys", s.setKey)
	prot("GET /p/{project}/{env}/keys/{key}", s.history)
	prot("POST /p/{project}/{env}/keys/{key}/delete", s.deleteKey)
	prot("POST /p/{project}/{env}/keys/{key}/reveal", s.reveal)
	prot("POST /p/{project}/{env}/keys/{key}/rollback", s.rollback)
	prot("POST /p/{project}/{env}/import", s.importKeys)
	prot("GET /p/{project}/{env}/export", s.export)
	prot("POST /p/{project}/{env}/targets", s.createTarget)
	prot("POST /p/{project}/{env}/targets/{target}/push", s.pushTarget)
	prot("POST /p/{project}/{env}/targets/{target}/check", s.checkTarget)
	prot("POST /p/{project}/{env}/targets/{target}/delete", s.deleteTarget)
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
	Targets      []store.Target
	Hosts        []store.Host
	Projects     []string
	Formats      map[string]string
}

type historyPage struct {
	page
	Project, Env, Key string
	Versions          []store.Version
}

type auditPage struct {
	page
	Entries []store.AuditEntry
}

var notices = map[string]string{
	"saved": "Key saved.", "deleted": "Key deleted.", "restored": "Version restored.",
	"target": "Target added.", "pushed": "Pushed.", "unpinned": "Host key forgotten. The next connect pins the new key.",
	"target-deleted": "Target deleted.", "host": "Host added.", "host-deleted": "Host deleted.",
}

func (s *Server) pg(r *http.Request, title string) page {
	tok := auth.CSRFToken(r)
	p := page{Title: title, CSRF: tok, Authed: tok != ""}
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
	case errors.Is(err, store.ErrInUse):
		return http.StatusConflict, err.Error()
	case errors.Is(err, store.ErrBadName), errors.Is(err, store.ErrBadReference):
		return http.StatusBadRequest, err.Error()
	}
	log.Printf("internal error: %v", err)
	return http.StatusInternalServerError, "Something went wrong. Check the server log."
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, msg := problem(err)
	s.message(w, r, status, msg)
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, msg string) {
	p := s.pg(r, "Error")
	p.Err = msg
	s.render(w, status, "message", p)
}

func (s *Server) formError(w http.ResponseWriter, r *http.Request, err error, view func(status int, msg string)) {
	status, msg := problem(err)
	if status == http.StatusNotFound || status == http.StatusInternalServerError {
		s.message(w, r, status, msg)
		return
	}
	view(status, msg)
}

func projectURL(project string) string { return "/p/" + url.PathEscape(project) }

func envURL(project, env string) string { return projectURL(project) + "/" + url.PathEscape(env) }

type loginPage struct {
	page
	Code bool
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", loginPage{page: page{Title: "Log in"}, Code: s.au.RequiresCode()})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	err := s.au.Login(w, r, r.PostFormValue("password"), r.PostFormValue("code"))
	var locked *auth.LockedError
	p := loginPage{page: page{Title: "Log in"}, Code: s.au.RequiresCode()}
	switch {
	case err == nil:
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.As(err, &locked):
		w.Header().Set("Retry-After", strconv.Itoa(int(locked.RetryAfter.Seconds())+1))
		p.Err = locked.Error()
		s.render(w, http.StatusTooManyRequests, "login", p)
	case errors.Is(err, auth.ErrInvalidCredentials):
		p.Err = "Wrong password."
		if p.Code {
			p.Err = "Wrong password or code."
		}
		s.render(w, http.StatusUnauthorized, "login", p)
	default:
		log.Printf("login: %v", err)
		p.Err = "Login is unavailable. Check the server log."
		s.render(w, http.StatusInternalServerError, "login", p)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.au.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	s.projectsView(w, r, http.StatusOK, "")
}

func (s *Server) projectsView(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	list, err := s.st.ListProjects()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := projectsPage{page: s.pg(r, "Projects"), Projects: list}
	p.Err = errMsg
	s.render(w, status, "projects", p)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.st.ListAudit(200)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "audit", auditPage{page: s.pg(r, "Audit log"), Entries: entries})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.st.CreateProject(name, actor); err != nil {
		s.formError(w, r, err, func(status int, msg string) { s.projectsView(w, r, status, msg) })
		return
	}
	http.Redirect(w, r, projectURL(name), http.StatusSeeOther)
}

func (s *Server) project(w http.ResponseWriter, r *http.Request) {
	s.projectView(w, r, http.StatusOK, "")
}

func (s *Server) projectView(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	project := r.PathValue("project")
	envs, err := s.st.ListEnvs(project)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := projectPage{page: s.pg(r, project), Project: project, Envs: envs}
	p.Err = errMsg
	s.render(w, status, "project", p)
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
		s.formError(w, r, err, func(status int, msg string) { s.projectView(w, r, status, msg) })
		return
	}
	http.Redirect(w, r, envURL(project, name), http.StatusSeeOther)
}

func (s *Server) env(w http.ResponseWriter, r *http.Request) {
	s.envView(w, r, http.StatusOK, envPage{})
}

func (s *Server) envView(w http.ResponseWriter, r *http.Request, status int, v envPage) {
	project, env := r.PathValue("project"), r.PathValue("env")
	keys, err := s.st.Keys(project, env)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	targets, err := s.st.ListTargets(project, env)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	hosts, err := s.st.ListHosts()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	projects, err := s.st.ListProjects()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.pg(r, project+"/"+env)
	p.Err = v.Err
	if v.Notice != "" {
		p.Notice = v.Notice
	}
	v.page, v.Project, v.Env, v.Keys, v.Targets, v.Hosts, v.Projects = p, project, env, keys, targets, hosts, projects
	v.Formats = formats.Formats
	s.render(w, status, "env", v)
}

func (s *Server) envError(w http.ResponseWriter, r *http.Request, err error) {
	s.formError(w, r, err, func(status int, msg string) {
		s.envView(w, r, status, envPage{page: page{Err: msg}})
	})
}

func (s *Server) deleteEnv(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	if r.PostFormValue("confirm") != env {
		s.envView(w, r, http.StatusBadRequest, envPage{page: page{Err: "Type the environment name to confirm deletion."}})
		return
	}
	if err := s.st.DeleteEnv(project, env, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, projectURL(project), http.StatusSeeOther)
}

func (s *Server) cloneEnv(w http.ResponseWriter, r *http.Request) {
	toProject, name := r.PostFormValue("project"), strings.TrimSpace(r.PostFormValue("name"))
	if err := s.st.CloneEnv(r.PathValue("project"), r.PathValue("env"), toProject, name, actor); err != nil {
		s.envError(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(toProject, name), http.StatusSeeOther)
}
