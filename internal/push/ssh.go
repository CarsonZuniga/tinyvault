package push

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/carsonzuniga/tinyvault/internal/store"
)

var ErrHostKeyMismatch = errors.New("host key does not match the pinned key")

type RemoteError struct{ Err error }

func (e *RemoteError) Error() string { return e.Err.Error() }

func (e *RemoteError) Unwrap() error { return e.Err }

// An empty HostKey trusts the host on first use.
func dial(key ed25519.PrivateKey, t store.Target) (*ssh.Client, string, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	addr := t.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	var seen string
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if t.HostKey != "" && t.HostKey != seen {
				return ErrHostKeyMismatch
			}
			return nil
		},
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, seen, fmt.Errorf("connect %s@%s: %w", t.User, addr, err)
	}
	return c, seen, nil
}

func writeFile(c *ssh.Client, path string, content []byte, postCmd string) error {
	script := `set -e; umask 077; t=$(mktemp ` + quote(path+".XXXXXX") + `); trap 'rm -f "$t"' EXIT; cat > "$t"; mv -f "$t" ` + quote(path)
	if _, err := run(c, script, content); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if postCmd != "" {
		if _, err := run(c, postCmd, nil); err != nil {
			return fmt.Errorf("file written, but post-command failed: %w", err)
		}
	}
	return nil
}

func readFile(c *ssh.Client, path string) ([]byte, bool, error) {
	out, err := run(c, "if [ -f "+quote(path)+" ]; then cat "+quote(path)+"; else exit 3; fi", nil)
	var exit *ssh.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitStatus() == 3:
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return out, true, nil
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
