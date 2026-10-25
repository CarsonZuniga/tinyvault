package push

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/carsonzuniga/tinyvault/internal/store"
)

func sshServer(t *testing.T, clientKey ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(clientKey.Marshal()) {
			return nil, errors.New("unknown key")
		}
		return nil, nil
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(nc, cfg)
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey()
}

func serveConn(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, reqs, _ := nch.Accept()
		go func() {
			defer ch.Close()
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				cmd := exec.Command("sh", "-c", string(req.Payload[4:]))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				status := uint32(0)
				if err := cmd.Run(); err != nil {
					status = 1
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						status = uint32(ee.ExitCode())
					}
				}
				ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
				return
			}
		}()
	}
}

func newPusher(t *testing.T) (p *Pusher, st *store.Store, hostKey string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.CreateProject("media", "admin")
	st.CreateEnv("media", "prod", "admin")
	st.Set("media", "prod", "A", "1", "admin")
	pub, _ := ssh.NewPublicKey(st.SSHKey().Public())
	addr, key := sshServer(t, pub)
	st.CreateHost(store.Host{Name: "box", User: "u", Address: addr}, "admin")
	return New(st), st, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func audited(t *testing.T, st *store.Store, action, detail string) bool {
	t.Helper()
	entries, _ := st.ListAudit(1)
	return len(entries) == 1 && entries[0].Action == action && entries[0].Detail == detail
}

func TestPushCheckAndPinning(t *testing.T) {
	p, st, hostKey := newPusher(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "it's here", "app.env")
	os.Mkdir(filepath.Dir(path), 0o755)
	st.CreateTarget("media", "prod", store.Target{
		Name: "nas", Host: store.Host{Name: "box"}, Path: path, Format: "dotenv",
		PostCmd: "touch " + quote(filepath.Join(dir, "ran")),
	}, "admin")

	if s, err := p.Check("media", "prod", "nas", "admin"); err != nil || s != Missing {
		t.Fatalf("check before push: %v %v", s, err)
	}
	if !audited(t, st, "target.check", string(Missing)) {
		t.Fatal("check not audited")
	}
	if pv, err := p.Preview("media", "prod", "nas", "admin"); err != nil || !pv.Missing || !audited(t, st, "target.preview", string(Missing)) {
		t.Fatalf("preview before push: %+v %v", pv, err)
	}
	if tg, _ := st.GetTarget("media", "prod", "nas"); tg.Host.HostKey != hostKey {
		t.Fatalf("host key not pinned on first use: %q", tg.Host.HostKey)
	}
	if err := p.Push("media", "prod", "nas", "admin"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "A=1\n" {
		t.Fatalf("written: %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatal("post-command did not run")
	}
	if left, _ := filepath.Glob(path + ".*"); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if !audited(t, st, "target.push", "") {
		t.Fatal("push not recorded")
	}

	for _, step := range []struct {
		change func()
		want   Status
	}{
		{func() {}, InSync},
		{func() { st.Set("media", "prod", "A", "2", "admin") }, Pending},
		{func() { os.WriteFile(path, []byte("A=hacked\n"), 0o600) }, Drifted},
	} {
		step.change()
		if s, err := p.Check("media", "prod", "nas", "admin"); err != nil || s != step.want {
			t.Fatalf("want %v, got %v %v", step.want, s, err)
		}
	}
	fresh := filepath.Join(dir, "fresh.json")
	os.WriteFile(fresh, []byte("{}"), 0o600)
	st.CreateTarget("media", "prod", store.Target{Name: "fresh", Host: store.Host{Name: "box"}, Path: fresh, Format: "json"}, "admin")
	if s, _ := p.Check("media", "prod", "fresh", "admin"); s != Unpushed {
		t.Fatalf("want never pushed, got %v", s)
	}

	st.ForgetHostKey("box", "admin")
	st.PinHostKey("media", "prod", "nas", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "admin")
	var remote *RemoteError
	if err := p.Push("media", "prod", "nas", "admin"); !errors.Is(err, ErrHostKeyMismatch) || !errors.As(err, &remote) {
		t.Fatalf("want host key mismatch, got %v", err)
	}
}

func TestPushFailures(t *testing.T) {
	p, st, _ := newPusher(t)
	dir := t.TempDir()
	for _, tg := range []store.Target{
		{Name: "nodir", Path: filepath.Join(dir, "nope", "x.env")},
		{Name: "postcmd", Path: filepath.Join(dir, "x.env"), PostCmd: "exit 7"},
	} {
		tg.Host, tg.Format = store.Host{Name: "box"}, "dotenv"
		st.CreateTarget("media", "prod", tg, "admin")
		var remote *RemoteError
		if err := p.Push("media", "prod", tg.Name, "admin"); !errors.As(err, &remote) {
			t.Fatalf("%s: want remote error, got %v", tg.Name, err)
		}
		if got, _ := st.GetTarget("media", "prod", tg.Name); got.PushedHash != "" {
			t.Fatalf("%s: failed push recorded", tg.Name)
		}
	}

	st.Import("media", "prod", map[string]string{"X": "${Y}", "Y": "${X}"}, "admin")
	st.CreateTarget("media", "prod", store.Target{
		Name: "cycle", Host: store.Host{Name: "box"}, Path: filepath.Join(dir, "c.env"),
		Format: "dotenv", Resolve: true,
	}, "admin")
	if err := p.Push("media", "prod", "cycle", "admin"); !errors.Is(err, store.ErrBadReference) {
		t.Fatalf("want bad reference, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "c.env")); err == nil {
		t.Fatal("unresolvable env was pushed")
	}
}
