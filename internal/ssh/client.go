// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// dialTimeout bounds the TCP+handshake phase of an SSH connection.
const dialTimeout = 20 * time.Second

// DialConfig describes how to reach a node over SSH.
type DialConfig struct {
	Host string
	Port int // 0 means 22
	User string
	// Signer authenticates coxswain to the node — coxswain's SSH identity.
	Signer cryptossh.Signer
	// Password, when set, authenticates with a one-time password instead of the
	// signer — used once to bootstrap a raw server (cox then installs its key and
	// switches to key auth). The password is never persisted. When Password is
	// set, Signer is ignored.
	Password string
	// KnownHostKey, if set, is the node's pinned host key in authorized_keys
	// format; the connection fails on mismatch. Empty enables trust-on-first-
	// use: any host key is accepted and recorded (see Conn.HostKey).
	KnownHostKey string
	// Dialer, when set, establishes the underlying TCP connection — used to
	// route the SSH session through an egress relay (decision 19) so the node
	// never sees coxswain's IP. SSH auth and host-key pinning remain end-to-end,
	// so the relay is a transparent pipe. nil means a direct net.Dialer.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Conn is an established SSH connection to a node.
type Conn struct {
	client  *cryptossh.Client
	hostKey string
}

// Dial opens an SSH connection to a node.
func Dial(ctx context.Context, cfg DialConfig) (*Conn, error) {
	if cfg.Signer == nil && cfg.Password == "" {
		return nil, fmt.Errorf("ssh: dial requires a signer or a password")
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))

	var observed string
	hostKeyCB := func(_ string, _ net.Addr, key cryptossh.PublicKey) error {
		observed = strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(key)))
		if cfg.KnownHostKey != "" && observed != strings.TrimSpace(cfg.KnownHostKey) {
			return fmt.Errorf("ssh: host key mismatch for %s", cfg.Host)
		}
		return nil
	}

	dial := cfg.Dialer
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	tcp, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	var auth []cryptossh.AuthMethod
	if cfg.Password != "" {
		// Many fresh hosts negotiate keyboard-interactive rather than the bare
		// "password" method, so offer both with the same secret.
		ki := cryptossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = cfg.Password
			}
			return answers, nil
		})
		auth = []cryptossh.AuthMethod{cryptossh.Password(cfg.Password), ki}
	} else {
		auth = []cryptossh.AuthMethod{cryptossh.PublicKeys(cfg.Signer)}
	}
	clientCfg := &cryptossh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         dialTimeout,
	}
	c, chans, reqs, err := cryptossh.NewClientConn(tcp, addr, clientCfg)
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("ssh: handshake %s: %w", addr, err)
	}
	return &Conn{client: cryptossh.NewClient(c, chans, reqs), hostKey: observed}, nil
}

// HostKey returns the node's SSH host key observed during Dial, in
// authorized_keys format. coxswain pins this for subsequent connections.
func (c *Conn) HostKey() string { return c.hostKey }

// Close terminates the connection.
func (c *Conn) Close() error { return c.client.Close() }

// Run executes a command, feeding stdin if non-nil, and returns its stdout.
// A non-zero exit includes the command's stderr in the error.
func (c *Conn) Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: open session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = sess.Close()
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return stdout.Bytes(), fmt.Errorf("ssh: command failed: %w: %s",
				err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}
}

// Upload writes data to remotePath on the node, creating the parent directory
// and setting the file mode.
func (c *Conn) Upload(ctx context.Context, remotePath string, data []byte, mode fs.FileMode) error {
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %o %s",
		shellQuote(path.Dir(remotePath)),
		shellQuote(remotePath),
		mode.Perm(),
		shellQuote(remotePath))
	if _, err := c.Run(ctx, cmd, data); err != nil {
		return fmt.Errorf("ssh: upload %s: %w", remotePath, err)
	}
	return nil
}

// shellQuote wraps s in single quotes, safe for POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellQuote wraps s in single quotes, safe to embed in a POSIX shell command
// run via Conn.Run.
func ShellQuote(s string) string { return shellQuote(s) }
