package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/carsonzuniga/tinyvault/internal/formats"
)

func keyURL(project, env, key string) string {
	return envURL(project, env) + "/keys/" + url.PathEscape(key)
}

func (s *Server) setKey(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	key := strings.TrimSpace(r.PostFormValue("key"))
	if err := s.st.Set(project, env, key, r.PostFormValue("value"), actor); err != nil {
		s.envError(w, r, err)
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
	s.envView(w, r, http.StatusOK, envPage{Revealed: &revealed{Key: key, Value: val}})
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	project, env, key := r.PathValue("project"), r.PathValue("env"), r.PathValue("key")
	versions, err := s.st.History(project, env, key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "history", historyPage{
		page: s.pg(r, key), Project: project, Env: env, Key: key, Versions: versions,
	})
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	project, env, key := r.PathValue("project"), r.PathValue("env"), r.PathValue("key")
	version, err := strconv.Atoi(r.PostFormValue("version"))
	if err != nil {
		s.message(w, r, http.StatusBadRequest, "Invalid version.")
		return
	}
	if err := s.st.Rollback(project, env, key, version, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, keyURL(project, env, key)+"?n=restored", http.StatusSeeOther)
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
		s.envView(w, r, http.StatusBadRequest, envPage{page: page{Err: "Could not parse input: " + err.Error()}})
		return
	}
	if err := s.st.Import(project, env, kv, actor); err != nil {
		s.envError(w, r, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s?n=imported&c=%d", envURL(project, env), len(kv)), http.StatusSeeOther)
}

func (s *Server) renderEnv(project, env, format string, resolve bool) (string, error) {
	m, err := s.st.GetAll(project, env)
	if err != nil {
		return "", err
	}
	if resolve {
		if m, err = formats.Resolve(m); err != nil {
			return "", fmt.Errorf("%w: cannot resolve references: %v", errBadInput, err)
		}
	}
	return formats.Render(format, project+"-"+env, m)
}

var errBadInput = errors.New("bad input")

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	format := r.URL.Query().Get("format")
	ext, ok := formats.Formats[format]
	if !ok {
		format, ext = "dotenv", formats.Formats["dotenv"]
	}
	body, err := s.renderEnv(project, env, format, r.URL.Query().Get("resolve") == "1")
	if errors.Is(err, errBadInput) {
		s.envView(w, r, http.StatusBadRequest, envPage{page: page{Err: err.Error()}})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.st.Audit(actor, "secret.export", project+"/"+env, format); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, project, env, ext))
	_, _ = w.Write([]byte(body))
}
