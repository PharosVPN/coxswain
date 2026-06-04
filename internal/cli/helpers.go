// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/egress"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/ssh"
	"github.com/PharosVPN/relay/onion"
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

// newCascadeCoordinator builds a cascade coordinator whose node dials are routed
// per target: each node is reached through its server's provision route (or
// direct), so the gRPC control plane honours the same routing as onboarding.
func newCascadeCoordinator(ctx context.Context, conn *sql.DB) (*cascade.Coordinator, error) {
	if _, err := newControlDialer(ctx, conn, nil); err != nil {
		return nil, err // fail fast if the controller cert can't be built
	}
	return cascade.New(conn, func(addr string) (cascade.NodeClient, error) {
		dialer, err := newControlDialer(ctx, conn, routeForControlAddr(ctx, conn, addr))
		if err != nil {
			return nil, err
		}
		return dialer.Dial(addr)
	}), nil
}

// newControlDialer builds the mTLS gRPC dialer for the node control plane,
// ensuring coxswain's CA and controller certificate exist. A non-empty route
// tunnels the dial through those relay hops; empty = direct.
func newControlDialer(ctx context.Context, conn *sql.DB, route []string) (*control.Dialer, error) {
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

	var opts []control.Option
	dial, err := egressDialerForRoute(ctx, conn, route)
	if err != nil {
		return nil, err
	}
	if dial != nil {
		opts = append(opts, control.WithContextDialer(func(dctx context.Context, addr string) (net.Conn, error) {
			return dial(dctx, "tcp", addr)
		}))
	}
	return control.NewDialer(chain, cc.KeyPEM, bundle.Root.CertPEM, opts...)
}

// relaysForRoute loads the relays named by an ordered route (relay ids), in that
// order — the hops coxswain tunnels a control-plane dial through. An empty route
// yields no relays (direct dial). Each hop must be an active remote egress
// relay; a missing or inactive hop is an error — there is no silent fallback to
// direct, so a chosen route either holds or fails loudly.
func relaysForRoute(ctx context.Context, conn *sql.DB, ids []string) ([]fleet.Relay, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	all, err := fleet.ListRelays(ctx, conn)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]fleet.Relay, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}
	chain := make([]fleet.Relay, 0, len(ids))
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("route relay %s not found", id)
		}
		if r.Kind != fleet.RelayKindRemote || r.Status != fleet.StatusActive || r.EgressEndpoint == "" {
			return nil, fmt.Errorf("route relay %s is not an active egress relay", id)
		}
		chain = append(chain, r)
	}
	return chain, nil
}

// controlDial dials a node host:port for the control plane, routed through the
// egress relays. Its signature matches net.Dialer.DialContext, so it drops into
// both the gRPC and SSH dial chokepoints.
type controlDial = func(ctx context.Context, network, addr string) (net.Conn, error)

// egressDialerForRoute returns the control-plane dialer for an ordered route of
// relay-id hops, or nil when the route is empty (direct dial — the default).
// When every hop is onion-capable it builds an onion circuit (decision 20) —
// each relay decrypts only its own layer, seeing neither coxswain's identity nor
// the full path; otherwise it builds the nested-TLS egress chain (decision 19).
func egressDialerForRoute(ctx context.Context, conn *sql.DB, ids []string) (controlDial, error) {
	chain, err := relaysForRoute(ctx, conn, ids)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, nil
	}
	if onionCapable(chain) {
		return onionDialer(chain)
	}
	tun, err := chainTunnel(ctx, conn, chain)
	if err != nil {
		return nil, err
	}
	return tun.DialContext, nil
}

// onionCapable reports whether every relay in the chain can serve as an onion
// hop (has both an onion endpoint and an onion public key).
func onionCapable(chain []fleet.Relay) bool {
	for _, r := range chain {
		if r.OnionEndpoint == "" || r.OnionPubKey == "" {
			return false
		}
	}
	return true
}

// onionDialer builds the onion-circuit dialer over the chain (decision 20). Each
// control dial opens a fresh circuit to the node target through every hop; the
// hop links are plain TCP, as the onion supplies confidentiality.
func onionDialer(chain []fleet.Relay) (controlDial, error) {
	hops := make([]onion.Hop, len(chain))
	for i, r := range chain {
		pub, err := onion.ParsePublicKey(r.OnionPubKey)
		if err != nil {
			return nil, fmt.Errorf("relay %s onion key: %w", r.ID, err)
		}
		hops[i] = onion.Hop{Addr: r.OnionEndpoint, OnionPub: pub}
	}
	firstHop := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return onion.Open(ctx, hops, addr, firstHop)
	}, nil
}

// chainTunnel builds the nested-TLS egress chain (decision 19): coxswain presents
// its controller cert to every hop and verifies each against the root.
func chainTunnel(ctx context.Context, conn *sql.DB, chain []fleet.Relay) (*egress.Tunnel, error) {
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	cc, _, err := pki.EnsureControllerCert(ctx, conn, bundle.Fleet)
	if err != nil {
		return nil, fmt.Errorf("controller cert: %w", err)
	}
	certChain := make([]byte, 0, len(cc.CertPEM)+len(bundle.Fleet.CertPEM))
	certChain = append(certChain, cc.CertPEM...)
	certChain = append(certChain, bundle.Fleet.CertPEM...)
	cert, err := tls.X509KeyPair(certChain, cc.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("egress client cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.Root.CertPEM) {
		return nil, errors.New("egress: no root CA in bundle")
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	}
	hops := make([]egress.Hop, len(chain))
	for i, r := range chain {
		hops[i] = egress.Hop{Endpoint: r.EgressEndpoint, TLS: base}
	}
	return egress.NewChain(hops)
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

// serverRoute returns a server's provision route (ordered relay-id hops), or nil
// (direct) for the empty server id or a missing server.
func serverRoute(ctx context.Context, conn *sql.DB, serverID string) []string {
	if serverID == "" {
		return nil
	}
	if s, err := fleet.GetServer(ctx, conn, serverID); err == nil {
		return s.Route
	}
	return nil
}

// nodeRoute returns the route coxswain reaches a node through — its server's
// route, or nil (direct) for a node with no server.
func nodeRoute(ctx context.Context, conn *sql.DB, node fleet.Node) []string {
	return serverRoute(ctx, conn, node.ServerID)
}

// routeForControlAddr maps a node's control address to its server's route, for
// per-target control-plane dialing. An unknown address yields nil (direct).
func routeForControlAddr(ctx context.Context, conn *sql.DB, addr string) []string {
	nodes, err := fleet.ListNodes(ctx, conn)
	if err != nil {
		return nil
	}
	for _, n := range nodes {
		if n.ControlAddr == addr {
			return serverRoute(ctx, conn, n.ServerID)
		}
	}
	return nil
}
