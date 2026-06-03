// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"

	"strings"

	"github.com/PharosVPN/coxswain/internal/api"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/server"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// cliDeployer implements api.Deployer using the same CA, SSH identity, and
// egress routing the CLI commands use. The admin server holds a reference so its
// /api/servers routes can onboard machines and deploy roles. Component binaries
// for API-driven deploys come from the configured binary URLs (the CLI's
// --binary upload path stays CLI-only).
type cliDeployer struct {
	cfg  config.Config
	conn *sql.DB
	geo  *geoip.Resolver
}

// regionFromIP derives a short region label (lowercased country code) from a
// host's IP, so a deployed component carries a sensible region without the
// admin typing one. Empty when geoip can't place the IP.
func (d cliDeployer) regionFromIP(host string) string {
	if loc, ok := d.geo.Lookup(host); ok {
		return strings.ToLower(loc.CountryCode)
	}
	return ""
}

func (d cliDeployer) Bootstrap(ctx context.Context, req api.BootstrapRequest) (fleet.Server, error) {
	id, _, err := ssh.EnsureIdentity(ctx, d.conn)
	if err != nil {
		return fleet.Server{}, err
	}
	dialer, err := newEgressDialer(ctx, d.conn)
	if err != nil {
		return fleet.Server{}, err
	}
	user := req.User
	if user == "" {
		user = d.cfg.Node.SSHUser
	}
	if user == "" {
		user = "root"
	}
	return server.Bootstrap(ctx, d.conn, id, server.BootstrapParams{
		Name:     req.Name,
		Region:   req.Region,
		Host:     req.Host,
		User:     user,
		Port:     req.Port,
		Password: req.Password,
		Dialer:   dialer,
	})
}

func (d cliDeployer) DeployNode(ctx context.Context, serverID, name, region string) (fleet.Node, error) {
	srv, bundle, id, dialer, err := d.deployContext(ctx, serverID)
	if err != nil {
		return fleet.Node{}, err
	}
	if region == "" {
		region = srv.Region
	}
	if region == "" {
		region = d.regionFromIP(srv.SSHHost)
	}
	spec, err := installSpec(d.cfg.Node.BinaryPath, "", d.cfg.Node.NodeBinaryURL, "node.binary_path or node.node_binary_url")
	if err != nil {
		return fleet.Node{}, err
	}
	res, err := server.DeployNode(ctx, d.conn, id, bundle, srv,
		deploy.AddParams{Name: name, Region: region, Install: spec}, dialer)
	return res.Node, err
}

func (d cliDeployer) DeployRelay(ctx context.Context, serverID string, req api.RelayDeployRequest) (fleet.Relay, error) {
	srv, bundle, id, dialer, err := d.deployContext(ctx, serverID)
	if err != nil {
		return fleet.Relay{}, err
	}
	spec, err := installSpec(d.cfg.Relay.BinaryPath, "", d.cfg.Relay.BinaryURL, "relay.binary_path or relay.binary_url")
	if err != nil {
		return fleet.Relay{}, err
	}

	region := req.Region
	if region == "" {
		region = srv.Region
	}
	if region == "" {
		region = d.regionFromIP(srv.SSHHost)
	}

	hostname := srv.SSHHost
	egressPort := req.EgressPort
	if egressPort == 0 {
		egressPort = 8456
	}
	onionPort := req.OnionPort
	if onionPort == 0 {
		onionPort = 8457
	}

	var egressEndpoint, onionEndpoint string
	egressHop := 0
	if req.Egress {
		egressEndpoint = net.JoinHostPort(hostname, strconv.Itoa(egressPort))
		egressHop, err = nextEgressHop(ctx, d.conn)
		if err != nil {
			return fleet.Relay{}, err
		}
	}
	if req.Onion {
		if !req.Egress {
			return fleet.Relay{}, fmt.Errorf("onion requires egress")
		}
		onionEndpoint = net.JoinHostPort(hostname, strconv.Itoa(onionPort))
	}
	// A non-self relay needs a reverse-tunnel ingress endpoint; self is egress/
	// onion only (DeployRelay forces NoIngress).
	endpoint := ""
	if !srv.IsSelf {
		endpoint = net.JoinHostPort(hostname, strconv.Itoa(deploy.ControlPort))
	}

	res, err := server.DeployRelay(ctx, d.conn, id, bundle, srv, deploy.RelayParams{
		Name:           req.Name,
		Region:         region,
		Endpoint:       endpoint,
		Hostname:       hostname,
		EgressEndpoint: egressEndpoint,
		EgressHop:      egressHop,
		OnionEndpoint:  onionEndpoint,
		Install:        spec,
	}, dialer)
	return res.Relay, err
}

// deployContext resolves a server and the shared CA/identity/dialer a deploy
// needs.
func (d cliDeployer) deployContext(ctx context.Context, serverID string) (fleet.Server, pki.Bundle, ssh.Identity, server.Dialer, error) {
	srv, err := fleet.GetServer(ctx, d.conn, serverID)
	if err != nil {
		return fleet.Server{}, pki.Bundle{}, ssh.Identity{}, nil, err
	}
	bundle, _, err := pki.EnsureCA(ctx, d.conn)
	if err != nil {
		return fleet.Server{}, pki.Bundle{}, ssh.Identity{}, nil, fmt.Errorf("load CA: %w", err)
	}
	id, _, err := ssh.EnsureIdentity(ctx, d.conn)
	if err != nil {
		return fleet.Server{}, pki.Bundle{}, ssh.Identity{}, nil, err
	}
	dialer, err := newEgressDialer(ctx, d.conn)
	if err != nil {
		return fleet.Server{}, pki.Bundle{}, ssh.Identity{}, nil, err
	}
	return srv, bundle, id, dialer, nil
}

// nextEgressHop returns the next free 1-based egress chain position.
func nextEgressHop(ctx context.Context, conn *sql.DB) (int, error) {
	relays, err := fleet.ListRelays(ctx, conn)
	if err != nil {
		return 0, err
	}
	hop := 0
	for _, r := range relays {
		if r.EgressEndpoint != "" && r.EgressHop > hop {
			hop = r.EgressHop
		}
	}
	return hop + 1, nil
}
