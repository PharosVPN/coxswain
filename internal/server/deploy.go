// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package server

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// DialServer opens a deploy connection to a server: a local exec channel for the
// is_self (controller) host, otherwise an SSH session authenticated with
// coxswain's key and the server's pinned host key (routed through the egress
// chain when dialer is set).
func DialServer(ctx context.Context, identity ssh.Identity, s fleet.Server, dialer Dialer) (deploy.Remote, error) {
	if s.IsSelf {
		return deploy.LocalRemote{}, nil
	}
	return ssh.Dial(ctx, ssh.DialConfig{
		Host:         s.SSHHost,
		Port:         s.SSHPort,
		User:         s.SSHUser,
		Signer:       identity.Signer,
		KnownHostKey: s.SSHHostKey,
		Dialer:       dialer,
	})
}

// DeployNode installs a node onto an onboarded server, reusing its access. SSH
// details and ServerID are taken from the server; region defaults to it.
func DeployNode(ctx context.Context, db *sql.DB, identity ssh.Identity, bundle pki.Bundle, s fleet.Server, p deploy.AddParams, dialer Dialer) (deploy.AddResult, error) {
	remote, err := DialServer(ctx, identity, s, dialer)
	if err != nil {
		return deploy.AddResult{}, err
	}
	defer remote.Close()

	p.SSHHost, p.SSHUser, p.SSHPort = s.SSHHost, s.SSHUser, s.SSHPort
	p.ServerID = s.ID
	if p.Region == "" {
		p.Region = s.Region
	}
	return deploy.AddNode(ctx, db, remote, bundle, p)
}

// DeployRelay installs a relay onto an onboarded server. On the controller's own
// host the client-facing ingress relay is skipped (NoIngress) so it doesn't
// fight the embedded relay for :443 — only egress/onion roles may run there.
func DeployRelay(ctx context.Context, db *sql.DB, identity ssh.Identity, bundle pki.Bundle, s fleet.Server, p deploy.RelayParams, dialer Dialer) (deploy.RelayResult, error) {
	if s.IsSelf {
		p.NoIngress = true
		if p.EgressEndpoint == "" && p.OnionEndpoint == "" {
			return deploy.RelayResult{}, fmt.Errorf("server: a relay on the controller host must be egress/onion only (no ingress)")
		}
	}
	remote, err := DialServer(ctx, identity, s, dialer)
	if err != nil {
		return deploy.RelayResult{}, err
	}
	defer remote.Close()

	p.SSHHost, p.SSHUser, p.SSHPort = s.SSHHost, s.SSHUser, s.SSHPort
	p.ServerID = s.ID
	if p.Region == "" {
		p.Region = s.Region
	}
	return deploy.AddRelay(ctx, db, remote, bundle, p)
}
