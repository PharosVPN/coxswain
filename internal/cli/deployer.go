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
	// Direct by default; the onboard rides the chosen route (relay hops) only
	// when the request supplies one, and that route is persisted on the server.
	dialer, err := egressDialerForRoute(ctx, d.conn, req.Route)
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

func (d cliDeployer) DeployNode(ctx context.Context, serverID, name, region string, route []string) (fleet.Node, error) {
	srv, bundle, id, dialer, err := d.deployContext(ctx, serverID, route)
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
	srv, bundle, id, dialer, err := d.deployContext(ctx, serverID, req.Route)
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

// UpdateNodeAgent re-installs the configured node binary on a node and restarts
// it (the API-driven counterpart of `cox nodes update`). The binary comes from
// node.binary_path / node.node_binary_url; the node is reached the same way the
// CLI reaches it (its stored route, or direct SSH).
func (d cliDeployer) UpdateNodeAgent(ctx context.Context, nodeID string) (fleet.Node, error) {
	node, err := fleet.GetNode(ctx, d.conn, nodeID)
	if err != nil {
		return fleet.Node{}, err
	}
	spec, err := installSpec(d.cfg.Node.BinaryPath, "", d.cfg.Node.NodeBinaryURL, "node.binary_path or node.node_binary_url")
	if err != nil {
		return fleet.Node{}, err
	}
	sshConn, err := dialNode(ctx, d.conn, node)
	if err != nil {
		return fleet.Node{}, err
	}
	defer sshConn.Close()
	return deploy.UpdateAgent(ctx, d.conn, sshConn, node, spec)
}

// UpdateRelayAgent re-installs the configured relay binary on a remote relay and
// restarts its services. The embedded relay has no server to reach over SSH and
// is upgraded with coxswain itself, so it is rejected here.
func (d cliDeployer) UpdateRelayAgent(ctx context.Context, relayID string) (fleet.Relay, error) {
	relay, err := fleet.GetRelay(ctx, d.conn, relayID)
	if err != nil {
		return fleet.Relay{}, err
	}
	if relay.ServerID == "" {
		return fleet.Relay{}, fmt.Errorf("relay %s has no server to update over SSH (the embedded relay is upgraded with coxswain)", relayID)
	}
	spec, err := installSpec(d.cfg.Relay.BinaryPath, "", d.cfg.Relay.BinaryURL, "relay.binary_path or relay.binary_url")
	if err != nil {
		return fleet.Relay{}, err
	}
	// Lifecycle agent updates dial direct (no per-action route; the persisted
	// onboard route was retired).
	srv, _, id, dialer, err := d.deployContext(ctx, relay.ServerID, nil)
	if err != nil {
		return fleet.Relay{}, err
	}
	remote, err := server.DialServer(ctx, id, srv, dialer)
	if err != nil {
		return fleet.Relay{}, err
	}
	defer remote.Close()
	return deploy.UpdateRelayAgent(ctx, d.conn, remote, relay, spec)
}

// deployContext resolves a server and the shared CA/identity a deploy needs,
// plus an SSH dialer built from the transient per-action route (relay-id hops,
// nil = direct). The route is not persisted — it applies only to this deploy.
func (d cliDeployer) deployContext(ctx context.Context, serverID string, route []string) (fleet.Server, pki.Bundle, ssh.Identity, server.Dialer, error) {
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
	dialer, err := egressDialerForRoute(ctx, d.conn, route)
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
