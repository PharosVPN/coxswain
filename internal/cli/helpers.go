// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"

	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/noderoute"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// openState loads the config file and opens the migrated state database. The
// caller must Close the returned *sql.DB.
func openState(cfgPath string) (config.Config, *sql.DB, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	// DataSource resolves to the configured Postgres DSN when set, else the
	// SQLite file at <state_dir>/app.db (the default). db.Open picks the driver.
	conn, err := db.Open(cfg.DataSource())
	if err != nil {
		return config.Config{}, nil, err
	}
	if err := db.Migrate(conn); err != nil {
		conn.Close()
		return config.Config{}, nil, err
	}
	// Backfill the audit hash chain (migration 00032) over any rows written
	// before tamper-evidence existed, so `cox audit verify` passes on an upgraded
	// database. Idempotent — a no-op once every row is hashed (and on a fresh DB).
	if err := audit.Backfill(context.Background(), conn); err != nil {
		conn.Close()
		return config.Config{}, nil, err
	}
	return cfg, conn, nil
}

// dialNew opens an SSH connection to a not-yet-enrolled node. The host key is
// trusted on first use and captured for later pinning. A non-empty route
// tunnels the SSH session through those relay hops; empty = direct (the default).
func dialNew(ctx context.Context, conn *sql.DB, host, user string, port int, route []string) (*ssh.Conn, error) {
	id, _, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		return nil, err
	}
	cfg := ssh.DialConfig{Host: host, Port: port, User: user, Signer: id.Signer}
	if err := applyRoute(ctx, conn, &cfg, route); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, cfg)
}

// dialNode opens an SSH connection to an enrolled node, verifying its pinned
// host key, tunnelled through the node's server route if it has one (else
// direct) — host-key pinning stays end-to-end.
func dialNode(ctx context.Context, conn *sql.DB, node fleet.Node) (*ssh.Conn, error) {
	id, _, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		return nil, err
	}
	cfg := ssh.DialConfig{
		Host:         node.SSHHost,
		Port:         node.SSHPort,
		User:         node.SSHUser,
		Signer:       id.Signer,
		KnownHostKey: node.SSHHostKey,
	}
	if err := applyRoute(ctx, conn, &cfg, nodeRoute(ctx, conn, node)); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, cfg)
}

// The gRPC control-plane dialer and route helpers live in internal/noderoute so
// the CLI, the admin API, and the reconcile sweep all reach a node the same way.
// These thin aliases/wrappers keep the rest of the cli package's call sites
// unchanged.

// controlDial matches net.Dialer.DialContext, the chokepoint both the gRPC and
// SSH dial paths plug into.
type controlDial = noderoute.ControlDial

func newCascadeCoordinator(ctx context.Context, conn *sql.DB) (*cascade.Coordinator, error) {
	return noderoute.NewCascadeCoordinator(ctx, conn)
}

func newControlDialer(ctx context.Context, conn *sql.DB, route []string) (*control.Dialer, error) {
	return noderoute.NewControlDialer(ctx, conn, route)
}

func egressDialerForRoute(ctx context.Context, conn *sql.DB, ids []string) (controlDial, error) {
	return noderoute.EgressDialerForRoute(ctx, conn, ids)
}

func nodeRoute(ctx context.Context, conn *sql.DB, node fleet.Node) []string {
	return noderoute.NodeRoute(ctx, conn, node)
}

// applyRoute points cfg.Dialer at the given route's relay hops; an empty route
// leaves cfg untouched (direct dial — the default).
func applyRoute(ctx context.Context, conn *sql.DB, cfg *ssh.DialConfig, route []string) error {
	dial, err := egressDialerForRoute(ctx, conn, route)
	if err != nil {
		return err
	}
	if dial != nil {
		cfg.Dialer = dial
	}
	return nil
}
