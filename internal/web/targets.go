package web

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/carsonzuniga/tinyvault/internal/push"
	"github.com/carsonzuniga/tinyvault/internal/store"
)

func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	t := store.Target{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		User:    strings.TrimSpace(r.PostFormValue("user")),
		Host:    strings.TrimSpace(r.PostFormValue("host")),
		Path:    strings.TrimSpace(r.PostFormValue("path")),
		Format:  r.PostFormValue("format"),
		Resolve: r.PostFormValue("resolve") == "1",
		PostCmd: strings.TrimSpace(r.PostFormValue("post_cmd")),
	}
	if err := s.st.CreateTarget(project, env, t, actor); err != nil {
		s.envError(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=target", http.StatusSeeOther)
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	if err := s.st.DeleteTarget(project, env, r.PathValue("target"), actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=target-deleted", http.StatusSeeOther)
}

func (s *Server) forgetHostKey(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	if err := s.st.ForgetHostKey(project, env, r.PathValue("target"), actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=unpinned", http.StatusSeeOther)
}

func (s *Server) pushTarget(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	t, body, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	hostKey, err := push.Write(s.st.SSHKey(), dest(t), t.Path, []byte(body), t.PostCmd)
	s.pinHostKey(project, env, t, hostKey)
	if err != nil {
		s.pushError(w, r, t, err)
		return
	}
	if err := s.st.RecordPush(project, env, t.Name, push.Hash([]byte(body)), actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=pushed", http.StatusSeeOther)
}

func (s *Server) checkTarget(w http.ResponseWriter, r *http.Request) {
	project, env := r.PathValue("project"), r.PathValue("env")
	t, body, ok := s.loadTarget(w, r)
	if !ok {
		return
	}
	status, hostKey, err := push.Check(s.st.SSHKey(), dest(t), t.Path, []byte(body), t.PushedHash)
	s.pinHostKey(project, env, t, hostKey)
	if err != nil {
		s.pushError(w, r, t, err)
		return
	}
	s.envView(w, r, http.StatusOK, envPage{page: page{Notice: t.Name + ": " + string(status) + "."}})
}

func (s *Server) loadTarget(w http.ResponseWriter, r *http.Request) (store.Target, string, bool) {
	project, env := r.PathValue("project"), r.PathValue("env")
	t, err := s.st.GetTarget(project, env, r.PathValue("target"))
	if err != nil {
		s.fail(w, r, err)
		return t, "", false
	}
	body, err := s.renderEnv(project, env, t.Format, t.Resolve)
	if errors.Is(err, errBadInput) {
		s.envView(w, r, http.StatusBadRequest, envPage{page: page{Err: err.Error()}})
		return t, "", false
	}
	if err != nil {
		s.fail(w, r, err)
		return t, "", false
	}
	return t, body, true
}

func (s *Server) pinHostKey(project, env string, t store.Target, hostKey string) {
	if t.HostKey != "" || hostKey == "" {
		return
	}
	if err := s.st.PinHostKey(project, env, t.Name, hostKey, actor); err != nil {
		log.Printf("pin host key for %s: %v", t.Name, err)
	}
}

func (s *Server) pushError(w http.ResponseWriter, r *http.Request, t store.Target, err error) {
	msg := t.Name + ": " + err.Error()
	if errors.Is(err, push.ErrHostKeyMismatch) {
		msg = t.Name + ": host key changed since it was pinned. If the host was rebuilt, use Forget host key and retry."
	}
	s.envView(w, r, http.StatusBadGateway, envPage{page: page{Err: msg}})
}

func dest(t store.Target) push.Dest {
	return push.Dest{User: t.User, Host: t.Host, HostKey: t.HostKey}
}
