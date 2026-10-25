package web

import (
	"errors"
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
	if err := s.pu.Push(project, env, r.PathValue("target"), actor); err != nil {
		s.pushError(w, r, err)
		return
	}
	http.Redirect(w, r, envURL(project, env)+"?n=pushed", http.StatusSeeOther)
}

func (s *Server) checkTarget(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
	status, err := s.pu.Check(r.PathValue("project"), r.PathValue("env"), target, actor)
	if err != nil {
		s.pushError(w, r, err)
		return
	}
	s.envView(w, r, http.StatusOK, envPage{page: page{Notice: target + ": " + string(status) + "."}})
}

func (s *Server) pushError(w http.ResponseWriter, r *http.Request, err error) {
	var remote *push.RemoteError
	if !errors.As(err, &remote) {
		s.envError(w, r, err)
		return
	}
	target := r.PathValue("target")
	msg := target + ": " + err.Error()
	if errors.Is(err, push.ErrHostKeyMismatch) {
		msg = target + ": host key changed since it was pinned. If the host was rebuilt, use Forget host key and retry."
	}
	s.envView(w, r, http.StatusBadGateway, envPage{page: page{Err: msg}})
}
