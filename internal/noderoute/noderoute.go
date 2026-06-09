// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package noderoute builds the routed gRPC control plane to fleet nodes: it
// resolves a node's egress route (direct, nested-TLS chain, or onion circuit)
// and constructs the mTLS control dialer and cascade coordinator that ride it.
//
// The route logic is shared by every control-plane caller — the CLI, the admin
// API, and the reconcile sweep — so a node is always reached the same way it was
// onboarded (its server's route, or direct). Only the gRPC/route helpers live
// here; SSH (deploy-channel) dialing stays in the cli package.
package noderoute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/egress"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/relay/onion"
)

// ControlDial dials a node host:port for the control plane, routed through the
// egress relays. Its signature matches net.Dialer.DialContext, so it drops into
// both the gRPC and SSH dial chokepoints.
type ControlDial = func(ctx context.Context, network, addr string) (net.Conn, error)

// NewControlDialer builds the mTLS gRPC dialer for the node control plane,
// ensuring coxswain's CA and controller certificate exist. A non-empty route
// tunnels the dial through those relay hops; empty = direct.
func NewControlDialer(ctx context.Context, conn *sql.DB, route []string) (*control.Dialer, error) {
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
	dial, err := EgressDialerForRoute(ctx, conn, route)
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

// NewCascadeCoordinator builds a cascade coordinator whose node dials are routed
// per target: each node is reached through its server's provision route (or
// direct), so the gRPC control plane honours the same routing as onboarding.
func NewCascadeCoordinator(ctx context.Context, conn *sql.DB) (*cascade.Coordinator, error) {
	if _, err := NewControlDialer(ctx, conn, nil); err != nil {
		return nil, err // fail fast if the controller cert can't be built
	}
	return cascade.New(conn, func(addr string) (cascade.NodeClient, error) {
		dialer, err := NewControlDialer(ctx, conn, RouteForControlAddr(ctx, conn, addr))
		if err != nil {
			return nil, err
		}
		return dialer.Dial(addr)
	}), nil
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

// EgressDialerForRoute returns the control-plane dialer for an ordered route of
// relay-id hops, or nil when the route is empty (direct dial — the default).
// When every hop is onion-capable it builds an onion circuit (decision 20) —
// each relay decrypts only its own layer, seeing neither coxswain's identity nor
// the full path; otherwise it builds the nested-TLS egress chain (decision 19).
func EgressDialerForRoute(ctx context.Context, conn *sql.DB, ids []string) (ControlDial, error) {
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
func onionDialer(chain []fleet.Relay) (ControlDial, error) {
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

// NodeRoute returns the route coxswain reaches a node's control plane through —
// the fleet-wide ACTIVE control path's relay hops, or nil (direct) when none is
// active. The route no longer depends on which server the node was deployed onto:
// control paths are first-class and swappable (DESIGN §3), so changing the active
// path reroutes the whole control plane at once, no re-onboard. The node arg is
// retained so call sites read naturally and a future per-node override can slot
// in here.
func NodeRoute(ctx context.Context, conn *sql.DB, _ fleet.Node) []string {
	return fleet.ActiveControlPathHops(ctx, conn)
}

// RouteForControlAddr returns the control-plane route for any node's control
// address — the active control path. It is address-independent today (one
// fleet-wide active path); the arg is kept for the per-target dialer contract.
func RouteForControlAddr(ctx context.Context, conn *sql.DB, _ string) []string {
	return fleet.ActiveControlPathHops(ctx, conn)
}
