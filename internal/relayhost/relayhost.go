// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package relayhost wires coxswain's account/sync gRPC service to the relay
// relay tier (DESIGN §2, M6b-2): an in-process embedded relay over an
// in-memory pipe, and a dialer for remote relays over the reverse tunnel.
package relayhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/PharosVPN/coxswain/internal/accountsvc"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/relay/core"
	"github.com/PharosVPN/relay/tunnel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AccountServer builds coxswain's AccountSync gRPC server with mTLS: it presents
// the coxswain-grpc leaf and requires a client cert chaining to the Fleet CA — the
// relay's cert. The same server value is served on the embedded pipe and on
// remote-tunnel substreams.
func AccountServer(db *sql.DB, grpcCert pki.ServiceCert, fleetCAPEM []byte) (*grpc.Server, error) {
	cert, err := tls.X509KeyPair(grpcCert.CertPEM, grpcCert.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("relayhost: gRPC cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(fleetCAPEM) {
		return nil, errors.New("relayhost: no Fleet CA certificate")
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	})))
	accountv1.RegisterAccountSyncServer(srv, accountsvc.New(db))
	return srv, nil
}

// EmbeddedConfig configures the in-process relay.
type EmbeddedConfig struct {
	// ClientListen is the public mTLS address for caravel clients.
	ClientListen string
	// RelayCert is the relay's dual-EKU Fleet-CA leaf.
	RelayCert pki.ServiceCert
	// DeviceCAPEM verifies caravel device leaves; FleetCAPEM verifies coxswain's
	// gRPC-leg cert.
	DeviceCAPEM []byte
	FleetCAPEM  []byte
}

// Embedded is a running in-process relay plus the gRPC server behind it.
type Embedded struct {
	relay *core.Relay
	srv   *grpc.Server
	pipe  *core.Pipe
}

// StartEmbedded runs srv behind an in-process relay over an in-memory pipe
// (DESIGN §2). mTLS runs over the pipe, so the embedded and remote auth paths
// are one path.
func StartEmbedded(srv *grpc.Server, cfg EmbeddedConfig) (*Embedded, error) {
	pipe := core.NewPipe()
	go func() { _ = srv.Serve(pipe) }()

	r, err := core.Start(core.Config{
		ClientListenAddr:  cfg.ClientListen,
		RelayCertPEM:      cfg.RelayCert.CertPEM,
		RelayKeyPEM:       cfg.RelayCert.KeyPEM,
		ClientTrustPEM:    cfg.DeviceCAPEM,
		BackendTrustPEM:   cfg.FleetCAPEM,
		BackendServerName: pki.GRPCServerName,
		BackendDialer:     pipe.DialContext,
	})
	if err != nil {
		srv.Stop()
		_ = pipe.Close()
		return nil, fmt.Errorf("relayhost: start embedded relay: %w", err)
	}
	return &Embedded{relay: r, srv: srv, pipe: pipe}, nil
}

// Addr is the relay's bound public address.
func (e *Embedded) Addr() net.Addr { return e.relay.Addr() }

// Stop drains the relay and the gRPC server.
func (e *Embedded) Stop() {
	e.relay.Stop()
	e.srv.Stop()
	_ = e.pipe.Close()
}

// RunRemote dials a remote relay and serves srv over the reverse tunnel,
// reconnecting forever until ctx is cancelled. coxswain keeps zero inbound ports —
// it dials out. relayAddr is the remote relay's tunnel listener.
func RunRemote(ctx context.Context, srv *grpc.Server, relayAddr string, relayCert pki.ServiceCert, fleetCAPEM []byte) error {
	cert, err := tls.X509KeyPair(relayCert.CertPEM, relayCert.KeyPEM)
	if err != nil {
		return fmt.Errorf("relayhost: tunnel cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(fleetCAPEM) {
		return errors.New("relayhost: no Fleet CA certificate")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	}
	return tunnel.DialAndAcceptLoop(ctx, relayAddr, tlsCfg,
		func(_ context.Context, lis *tunnel.SessionListener) error {
			return srv.Serve(lis)
		}, log.Printf, nil)
}
