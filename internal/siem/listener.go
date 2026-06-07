// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package siem

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"

	monitorv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/monitor/v1"
	"github.com/PharosVPN/coxswain/internal/live"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Options configures the optional inbound SIEM gRPC listener. The zero Options
// (empty Listen) means disabled — coxswain opens no inbound port.
type Options struct {
	// Listen is the address the SIEM gRPC server binds (e.g. ":9443" or
	// "0.0.0.0:9443"). Empty disables the listener entirely (the default).
	Listen string
	// TLSCert / TLSKey are PEM file paths for transport TLS. Both must be set to
	// enable TLS; otherwise the listener is plaintext (acceptable only behind an
	// SSH tunnel / on loopback — production SIEM use should set TLS).
	TLSCert string
	TLSKey  string
}

// Enabled reports whether a SIEM listener is configured.
func (o Options) Enabled() bool { return o.Listen != "" }

// TLSEnabled reports whether transport TLS is configured (both cert and key).
func (o Options) TLSEnabled() bool { return o.TLSCert != "" && o.TLSKey != "" }

// Listener is a running SIEM gRPC server. Stop it on shutdown.
type Listener struct {
	grpc *grpc.Server
	lis  net.Listener
	srv  *Server
	addr string
	tls  bool
}

// Addr is the address the listener is bound to.
func (l *Listener) Addr() string { return l.addr }

// TLS reports whether the listener terminates TLS.
func (l *Listener) TLS() bool { return l.tls }

// Dropped reports the backpressure drop count across all SIEM consumers.
func (l *Listener) Dropped() int64 { return l.srv.Dropped() }

// Serve runs the gRPC server until Stop is called or the listener errors. It
// blocks; run it in a goroutine. A clean Stop returns nil.
func (l *Listener) Serve() error { return l.grpc.Serve(l.lis) }

// Stop gracefully stops the server and releases the port.
func (l *Listener) Stop() { l.grpc.GracefulStop() }

// Start binds opts.Listen and builds a gRPC server that streams the live hub's
// events to authenticated monitor-scope consumers. It does NOT begin serving —
// the caller runs Serve() in a goroutine, so a bind error surfaces immediately
// here while serving happens in the background. onSubscribe (optional) records
// an audit row per accepted consumer. Returns (nil, nil) when opts is disabled.
func Start(db *sql.DB, hub *live.Hub, opts Options, onSubscribe func(ctx context.Context)) (*Listener, error) {
	if !opts.Enabled() {
		return nil, nil
	}

	var serverOpts []grpc.ServerOption
	serverOpts = append(serverOpts, grpc.ChainStreamInterceptor(AuthInterceptor(db)))

	useTLS := opts.TLSEnabled()
	if useTLS {
		cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("siem: load TLS keypair: %w", err)
		}
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}

	lis, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("siem: listen on %s: %w", opts.Listen, err)
	}

	gs := grpc.NewServer(serverOpts...)
	srv := NewServer(hub, onSubscribe)
	monitorv1.RegisterMonitorStreamServer(gs, srv)

	return &Listener{grpc: gs, lis: lis, srv: srv, addr: lis.Addr().String(), tls: useTLS}, nil
}
