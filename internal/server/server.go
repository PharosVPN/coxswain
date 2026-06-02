// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package server is coxswain's machine-onboarding layer (DESIGN §5): it turns a
// raw host (reached once with a one-time password) into a managed Server by
// installing coxswain's SSH key and pinning the host key, then deploys node and
// relay roles onto servers reusing that key-based access. The controller's own
// host is an is_self server whose roles deploy locally rather than over SSH.
package server

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// Dialer establishes the underlying TCP connection for an SSH session — used to
// route bootstrap/deploy SSH through the egress relay chain (decision 19). nil
// means a direct dial.
type Dialer = func(ctx context.Context, network, addr string) (net.Conn, error)

// BootstrapParams are the inputs to Bootstrap.
type BootstrapParams struct {
	Name     string // generated from Host if empty
	Region   string
	Host     string // required — IP/hostname to SSH into (and the server's address)
	User     string // required — SSH login user
	Port     int    // 0 means 22
	Password string // required — the one-time password; never persisted
	Dialer   Dialer // optional egress dialer
}

// Bootstrap onboards a raw machine: it SSHes in with the one-time password,
// installs coxswain's SSH public key, pins the host key (TOFU), verifies key
// auth works, and records the Server. The password is used once and never
// stored. A host key that changes between the password leg and the key leg
// aborts the bootstrap (possible MITM) — the admin must retry.
func Bootstrap(ctx context.Context, db *sql.DB, identity ssh.Identity, p BootstrapParams) (fleet.Server, error) {
	if p.Host == "" || p.User == "" {
		return fleet.Server{}, fmt.Errorf("server: host and user are required")
	}
	if p.Password == "" {
		return fleet.Server{}, fmt.Errorf("server: a one-time password is required to onboard a new server")
	}

	// 1. Password dial; capture the host key (TOFU).
	pwConn, err := ssh.Dial(ctx, ssh.DialConfig{
		Host: p.Host, Port: p.Port, User: p.User, Password: p.Password, Dialer: p.Dialer,
	})
	if err != nil {
		return fleet.Server{}, fmt.Errorf("server: password login to %s: %w", p.Host, err)
	}
	hostKey := pwConn.HostKey()

	// 2. Install coxswain's key into authorized_keys, idempotently.
	if _, err := pwConn.Run(ctx, installKeyCmd(identity.AuthorizedKey), nil); err != nil {
		pwConn.Close()
		return fleet.Server{}, fmt.Errorf("server: install key on %s: %w", p.Host, err)
	}
	pwConn.Close()

	// 3. Re-dial with key auth, pinning the host key, to verify the install and
	//    confirm the host key end-to-end.
	keyConn, err := ssh.Dial(ctx, ssh.DialConfig{
		Host: p.Host, Port: p.Port, User: p.User, Signer: identity.Signer,
		KnownHostKey: hostKey, Dialer: p.Dialer,
	})
	if err != nil {
		return fleet.Server{}, fmt.Errorf("server: key auth to %s failed after install: %w", p.Host, err)
	}
	if keyConn.HostKey() != hostKey {
		keyConn.Close()
		return fleet.Server{}, fmt.Errorf("server: host key for %s changed during bootstrap — aborting (retry)", p.Host)
	}
	keyConn.Close()

	// 4. Persist. Re-onboarding the same host updates the existing row rather
	//    than creating a duplicate (the key install is idempotent too).
	if existing, gErr := fleet.GetServerByHost(ctx, db, p.Host); gErr == nil {
		existing.SSHUser = p.User
		existing.SSHPort = p.Port
		existing.SSHHostKey = hostKey
		existing.Status = fleet.StatusActive
		if p.Name != "" {
			existing.Name = p.Name
		}
		if p.Region != "" {
			existing.Region = p.Region
		}
		return fleet.UpdateServer(ctx, db, existing)
	}
	return fleet.CreateServer(ctx, db, fleet.Server{
		Name:       p.Name,
		Region:     p.Region,
		SSHHost:    p.Host,
		SSHUser:    p.User,
		SSHPort:    p.Port,
		SSHHostKey: hostKey,
		Status:     fleet.StatusActive,
	})
}

// installKeyCmd builds the idempotent POSIX command that adds the authorized key
// to the login user's authorized_keys (created with safe perms if absent).
func installKeyCmd(authorizedKey string) string {
	k := ssh.ShellQuote(authorizedKey)
	return "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && " +
		"chmod 600 ~/.ssh/authorized_keys && " +
		"(grep -qxF " + k + " ~/.ssh/authorized_keys || printf '%s\\n' " + k + " >> ~/.ssh/authorized_keys)"
}
