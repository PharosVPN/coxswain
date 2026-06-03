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
	Password string // optional — a one-time password; empty means key auth (cox's key already installed). Never persisted.
	Dialer   Dialer // optional egress dialer
}

// Bootstrap onboards a raw machine and records it as a Server, by one of two
// methods:
//
//   - Password: SSH in with the one-time password, install coxswain's SSH key,
//     then re-dial with the key to verify it and pin the host key. The password
//     is used once and never stored. A host key that changes between the two
//     legs aborts the bootstrap (possible MITM).
//   - Key (Password empty): coxswain's key is already on the host (e.g. added
//     as the droplet's login key at creation) — dial with the key and pin the
//     host key on first use.
func Bootstrap(ctx context.Context, db *sql.DB, identity ssh.Identity, p BootstrapParams) (fleet.Server, error) {
	if p.Host == "" || p.User == "" {
		return fleet.Server{}, fmt.Errorf("server: host and user are required")
	}

	var hostKey string
	if p.Password != "" {
		// Password leg: log in, install coxswain's key, capture the host key.
		pwConn, err := ssh.Dial(ctx, ssh.DialConfig{
			Host: p.Host, Port: p.Port, User: p.User, Password: p.Password, Dialer: p.Dialer,
		})
		if err != nil {
			return fleet.Server{}, fmt.Errorf("server: password login to %s: %w", p.Host, err)
		}
		hostKey = pwConn.HostKey()
		if _, err := pwConn.Run(ctx, installKeyCmd(identity.AuthorizedKey), nil); err != nil {
			pwConn.Close()
			return fleet.Server{}, fmt.Errorf("server: install key on %s: %w", p.Host, err)
		}
		pwConn.Close()

		// Key leg: verify the install worked and confirm the host key end-to-end.
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
	} else {
		// Key-only: coxswain's key is already installed. Dial with it and pin
		// the host key on first use (TOFU).
		keyConn, err := ssh.Dial(ctx, ssh.DialConfig{
			Host: p.Host, Port: p.Port, User: p.User, Signer: identity.Signer, Dialer: p.Dialer,
		})
		if err != nil {
			return fleet.Server{}, fmt.Errorf("server: key login to %s failed — add coxswain's SSH key to the host (or onboard with a password): %w", p.Host, err)
		}
		hostKey = keyConn.HostKey()
		keyConn.Close()
	}

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
