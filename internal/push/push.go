package push

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrHostKeyMismatch = errors.New("host key does not match the pinned key")

// An empty HostKey trusts the host on first use.
type Dest struct {
	User, Host, HostKey string
}

type Status string

const (
	InSync   Status = "in sync"
	Pending  Status = "vault has unpushed changes"
	Drifted  Status = "changed on target since last push"
	Missing  Status = "missing on target"
	Unpushed Status = "never pushed"
)

func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func PublicKey(key ed25519.PrivateKey) string {
	pub, _ := ssh.NewPublicKey(key.Public())
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " tinyvault"
}

func Write(key ed25519.PrivateKey, d Dest, path string, content []byte, postCmd string) (string, error) {
	c, hostKey, err := dial(key, d)
	if err != nil {
		return hostKey, err
	}
	defer c.Close()
	script := `set -e; umask 077; t=$(mktemp ` + quote(path+".XXXXXX") + `); trap 'rm -f "$t"' EXIT; cat > "$t"; mv -f "$t" ` + quote(path)
	if _, err := run(c, script, content); err != nil {
		return hostKey, fmt.Errorf("write %s: %w", path, err)
	}
	if postCmd != "" {
		if _, err := run(c, postCmd, nil); err != nil {
			return hostKey, fmt.Errorf("file written, but post-command failed: %w", err)
		}
	}
	return hostKey, nil
}

func Check(key ed25519.PrivateKey, d Dest, path string, want []byte, pushedHash string) (Status, string, error) {
	c, hostKey, err := dial(key, d)
	if err != nil {
		return "", hostKey, err
	}
	defer c.Close()
	out, err := run(c, "if [ -f "+quote(path)+" ]; then cat "+quote(path)+"; else exit 3; fi", nil)
	var exit *ssh.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitStatus() == 3:
		return Missing, hostKey, nil
	case err != nil:
		return "", hostKey, fmt.Errorf("read %s: %w", path, err)
	}
	remote := Hash(out)
	switch {
	case remote == Hash(want):
		return InSync, hostKey, nil
	case pushedHash == "":
		return Unpushed, hostKey, nil
	case remote == pushedHash:
		return Pending, hostKey, nil
	}
	return Drifted, hostKey, nil
}

func dial(key ed25519.PrivateKey, d Dest) (*ssh.Client, string, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	addr := d.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	var seen string
	cfg := &ssh.ClientConfig{
		User:    d.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if d.HostKey != "" && d.HostKey != seen {
				return ErrHostKeyMismatch
			}
			return nil
		},
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, seen, fmt.Errorf("connect %s@%s: %w", d.User, addr, err)
	}
	return c, seen, nil
}

func run(c *ssh.Client, cmd string, stdin []byte) ([]byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdin = bytes.NewReader(stdin)
	sess.Stdout, sess.Stderr = &stdout, &stderr
	if err := sess.Run(cmd); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, truncate(msg, 300))
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
