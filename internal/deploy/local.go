// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package deploy

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LocalRemote runs deploy commands on the controller's own host instead of over
// SSH — the Remote used when deploying a node/relay onto the is_self server. It
// requires the controller process to run as root (it writes /usr/local/bin and
// /etc/systemd and runs systemctl). HostKey is empty: there is no SSH host key
// for a local deploy, and the resulting node is reached over the loopback/local
// control address, never SSH-dialed.
type LocalRemote struct{}

// Run executes cmd through /bin/sh, feeding stdin if non-nil, returning stdout.
// A non-zero exit includes stderr in the error (mirrors ssh.Conn.Run).
func (LocalRemote) Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("local: command failed: %w: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Upload writes data to path locally, creating the parent directory and setting
// the file mode.
func (LocalRemote) Upload(_ context.Context, path string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("local: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, mode.Perm()); err != nil {
		return fmt.Errorf("local: write %s: %w", path, err)
	}
	return nil
}

// HostKey returns "" — a local deploy has no SSH host key.
func (LocalRemote) HostKey() string { return "" }

// Close is a no-op.
func (LocalRemote) Close() error { return nil }
