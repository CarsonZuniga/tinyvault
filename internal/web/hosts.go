package web

import (
	"net/http"
	"strings"

	"github.com/carsonzuniga/tinyvault/internal/store"
)

type hostsPage struct {
	page
	Hosts     []store.Host
	PublicKey string
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	s.hostsView(w, r, http.StatusOK, "")
}

func (s *Server) hostsView(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	hosts, err := s.st.ListHosts()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := hostsPage{page: s.pg(r, "Hosts"), Hosts: hosts, PublicKey: s.pu.PublicKey()}
	p.Err = errMsg
	s.render(w, status, "hosts", p)
}

func (s *Server) hostsError(w http.ResponseWriter, r *http.Request, err error) {
	s.formError(w, r, err, func(status int, msg string) { s.hostsView(w, r, status, msg) })
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	h := store.Host{
		Name:    strings.TrimSpace(r.PostFormValue("name")),
		User:    strings.TrimSpace(r.PostFormValue("user")),
		Address: strings.TrimSpace(r.PostFormValue("address")),
	}
	if err := s.st.CreateHost(h, actor); err != nil {
		s.hostsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/hosts?n=host", http.StatusSeeOther)
}

func (s *Server) forgetHostKey(w http.ResponseWriter, r *http.Request) {
	if err := s.st.ForgetHostKey(r.PathValue("host"), actor); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/hosts?n=unpinned", http.StatusSeeOther)
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteHost(r.PathValue("host"), actor); err != nil {
		s.hostsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/hosts?n=host-deleted", http.StatusSeeOther)
}
