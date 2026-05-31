// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"

	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// openState loads the config file and opens the migrated state database. The
// caller must Close the returned *sql.DB.
func openState(cfgPath string) (config.Config, *sql.DB, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	conn, err := db.Open(filepath.Join(cfg.StateDir, "app.db"))
	if err != nil {
		return config.Config{}, nil, err
	}
	if err := db.Migrate(conn); err != nil {
		conn.Close()
		return config.Config{}, nil, err
	}
	return cfg, conn, nil
}

// dialNew opens an SSH connection to a not-yet-enrolled node. The host key is
// trusted on first use and captured for later pinning.
func dialNew(ctx context.Context, conn *sql.DB, host, user string, port int) (*ssh.Conn, error) {
	id, _, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, ssh.DialConfig{
		Host: host, Port: port, User: user, Signer: id.Signer,
	})
}

// dialNode opens an SSH connection to an enrolled node, verifying its pinned
// host key.
func dialNode(ctx context.Context, conn *sql.DB, node fleet.Node) (*ssh.Conn, error) {
	id, _, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, ssh.DialConfig{
		Host:         node.SSHHost,
		Port:         node.SSHPort,
		User:         node.SSHUser,
		Signer:       id.Signer,
		KnownHostKey: node.SSHHostKey,
	})
}

// newCascadeCoordinator builds a cascade coordinator backed by the state DB and
// the buoy control-plane dialer.
func newCascadeCoordinator(ctx context.Context, conn *sql.DB) (*cascade.Coordinator, error) {
	dialer, err := newControlDialer(ctx, conn)
	if err != nil {
		return nil, err
	}
	return cascade.New(conn, func(addr string) (cascade.NodeClient, error) {
		return dialer.Dial(addr)
	}), nil
}

// newControlDialer builds the mTLS gRPC dialer for the buoy control plane,
// ensuring coxswain's CA and controller certificate exist.
func newControlDialer(ctx context.Context, conn *sql.DB) (*control.Dialer, error) {
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	cc, _, err := pki.EnsureControllerCert(ctx, conn, bundle.Fleet)
	if err != nil {
		return nil, fmt.Errorf("controller cert: %w", err)
	}
	chain := make([]byte, 0, len(cc.CertPEM)+len(bundle.Fleet.CertPEM))
	chain = append(chain, cc.CertPEM...)
	chain = append(chain, bundle.Fleet.CertPEM...)
	return control.NewDialer(chain, cc.KeyPEM, bundle.Root.CertPEM)
}
