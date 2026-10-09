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

func TestWriteCheckAndPinning(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	addr, hostKey := sshServer(t, signer.PublicKey())
	dir := t.TempDir()
	path := filepath.Join(dir, "it's here", "app.env")
	os.Mkdir(filepath.Dir(path), 0o755)
	d := Dest{User: "u", Host: addr}

	if st, _, err := Check(key, d, path, []byte("A=1\n"), ""); err != nil || st != Missing {
		t.Fatalf("check before push: %v %v", st, err)
	}
	seen, err := Write(key, d, path, []byte("A=1\n"), "touch "+quote(filepath.Join(dir, "ran")))
	if err != nil {
		t.Fatal(err)
	}
	if seen != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))) {
		t.Fatalf("host key not reported: %q", seen)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("written file: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatal("post-command did not run")
	}
	if left, _ := filepath.Glob(path + ".*"); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}

	d.HostKey = seen
	pushed := Hash([]byte("A=1\n"))
	if st, _, _ := Check(key, d, path, []byte("A=1\n"), pushed); st != InSync {
		t.Fatalf("want in sync, got %v", st)
	}
	if st, _, _ := Check(key, d, path, []byte("A=2\n"), pushed); st != Pending {
		t.Fatalf("want pending, got %v", st)
	}
	os.WriteFile(path, []byte("A=hacked\n"), 0o600)
	if st, _, _ := Check(key, d, path, []byte("A=1\n"), pushed); st != Drifted {
		t.Fatalf("want drifted, got %v", st)
	}

	if _, err := Write(key, d, filepath.Join(dir, "nope", "x.env"), nil, ""); err == nil {
		t.Fatal("write into missing dir must fail")
	}
	if _, err := Write(key, d, path, nil, "exit 7"); err == nil {
		t.Fatal("failing post-command must be reported")
	}

	d.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if _, err := Write(key, d, path, []byte("x"), ""); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("want host key mismatch, got %v", err)
	}
}
