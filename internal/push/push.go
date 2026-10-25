package push

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/carsonzuniga/tinyvault/internal/store"
)

type Status string

const (
	InSync   Status = "in sync"
	Pending  Status = "vault has unpushed changes"
	Drifted  Status = "changed on target since last push"
	Missing  Status = "missing on target"
	Unpushed Status = "never pushed"
)

type Pusher struct{ st *store.Store }

func New(st *store.Store) *Pusher { return &Pusher{st: st} }

func (p *Pusher) PublicKey() string {
	pub, _ := ssh.NewPublicKey(p.st.SSHKey().Public())
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " tinyvault"
}

func (p *Pusher) Push(project, env, target, actor string) error {
	t, body, err := p.export(project, env, target, actor, "push "+target)
	if err != nil {
		return err
	}
	c, err := p.connect(project, env, t, actor)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := writeFile(c, t.Path, body, t.PostCmd); err != nil {
		return &RemoteError{err}
	}
	return p.st.RecordPush(project, env, t.Name, hash(body), actor)
}

func (p *Pusher) Check(project, env, target, actor string) (Status, error) {
	t, body, err := p.export(project, env, target, actor, "check "+target)
	if err != nil {
		return "", err
	}
	c, err := p.connect(project, env, t, actor)
	if err != nil {
		return "", err
	}
	defer c.Close()
	remote, found, err := readFile(c, t.Path)
	if err != nil {
		return "", &RemoteError{err}
	}
	status := compare(remote, found, body, t.PushedHash)
	if err := p.st.Audit(actor, "target.check", project+"/"+env+"/"+t.Name, string(status)); err != nil {
		return "", err
	}
	return status, nil
}

func (p *Pusher) export(project, env, target, actor, detail string) (store.Target, []byte, error) {
	t, err := p.st.GetTarget(project, env, target)
	if err != nil {
		return t, nil, err
	}
	body, err := p.st.Export(project, env, t.Format, t.Resolve, actor, detail)
	return t, []byte(body), err
}

func (p *Pusher) connect(project, env string, t store.Target, actor string) (*ssh.Client, error) {
	c, seen, err := dial(p.st.SSHKey(), t)
	if t.HostKey == "" && seen != "" {
		if err := p.st.PinHostKey(project, env, t.Name, seen, actor); err != nil {
			log.Printf("pin host key for %s: %v", t.Name, err)
		}
	}
	if err != nil {
		return nil, &RemoteError{err}
	}
	return c, nil
}

func compare(remote []byte, found bool, want []byte, pushedHash string) Status {
	switch h := hash(remote); {
	case !found:
		return Missing
	case h == hash(want):
		return InSync
	case pushedHash == "":
		return Unpushed
	case h == pushedHash:
		return Pending
	}
	return Drifted
}

func hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
