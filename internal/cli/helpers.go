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
	"sort"

	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/egress"
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
// trusted on first use and captured for later pinning. If an egress relay is
// enrolled, the SSH session is routed through it (decision 19).
func dialNew(ctx context.Context, conn *sql.DB, host, user string, port int) (*ssh.Conn, error) {
	id, _, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		return nil, err
	}
	cfg := ssh.DialConfig{Host: host, Port: port, User: user, Signer: id.Signer}
	if err := routeSSHThroughEgress(ctx, conn, &cfg); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, cfg)
}

// dialNode opens an SSH connection to an enrolled node, verifying its pinned
// host key. If an egress relay is enrolled, the SSH session is routed through
// it (decision 19) — host-key pinning stays end-to-end.
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
	if err := routeSSHThroughEgress(ctx, conn, &cfg); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, cfg)
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

	var opts []control.Option
	tunnel, err := newEgressTunnel(ctx, conn)
	if err != nil {
		return nil, err
	}
	if tunnel != nil {
		opts = append(opts, control.WithContextDialer(func(dctx context.Context, addr string) (net.Conn, error) {
			return tunnel.DialContext(dctx, "tcp", addr)
		}))
	}
	return control.NewDialer(chain, cc.KeyPEM, bundle.Root.CertPEM, opts...)
}

// egressRelays returns the relays coxswain should route its control plane
// through (DESIGN §3, decision 19), in chain order — every active remote relay
// carrying an egress endpoint, sorted by EgressHop ascending (hop 1 closest to
// coxswain, the last hop reaches the node), ties broken by creation order for
// determinism. Empty means direct dial.
func egressRelays(ctx context.Context, conn *sql.DB) ([]fleet.Relay, error) {
	relays, err := fleet.ListRelays(ctx, conn) // already ordered by created_at
	if err != nil {
		return nil, err
	}
	var chain []fleet.Relay
	for _, r := range relays {
		if r.Kind == fleet.RelayKindRemote && r.Status == fleet.StatusActive && r.EgressEndpoint != "" {
			chain = append(chain, r)
		}
	}
	sort.SliceStable(chain, func(i, j int) bool { return chain[i].EgressHop < chain[j].EgressHop })
	return chain, nil
}

// newEgressTunnel builds the egress tunnel through the enrolled egress relays,
// or returns nil when none is configured (direct dial). With several relays it
// is a chain — coxswain → relay0 → … → relayN → node — so no single relay sees
// both coxswain's address and the node's (ladder step 2). coxswain presents its
// controller cert (Fleet-CA leaf) to every hop and verifies each relay against
// the root; a relay only needs a valid Fleet-CA client cert on this leg (it is
// otherwise protocol-blind).
func newEgressTunnel(ctx context.Context, conn *sql.DB) (*egress.Tunnel, error) {
	chain, err := egressRelays(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("egress relay lookup: %w", err)
	}
	if len(chain) == 0 {
		return nil, nil
	}
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

// routeSSHThroughEgress points cfg.Dialer at the enrolled egress relay, if one
// exists; otherwise it leaves cfg untouched (direct dial).
func routeSSHThroughEgress(ctx context.Context, conn *sql.DB, cfg *ssh.DialConfig) error {
	tunnel, err := newEgressTunnel(ctx, conn)
	if err != nil {
		return err
	}
	if tunnel != nil {
		cfg.Dialer = tunnel.DialContext
	}
	return nil
}
