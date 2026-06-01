// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package control is coxswain's outbound gRPC control plane: it dials each buoy
// node over mTLS and drives the NodeControl service (DESIGN §6, §7).
package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Dialer opens mTLS gRPC connections to buoy nodes. It is built once from
// coxswain's controller certificate and reused for every node.
type Dialer struct {
	creds         credentials.TransportCredentials
	contextDialer func(ctx context.Context, addr string) (net.Conn, error)
}

// Option configures a Dialer.
type Option func(*Dialer)

// WithContextDialer routes the gRPC connection's underlying transport through
// dial instead of a direct TCP connect — used to reach nodes through an egress
// relay (decision 19) so a node never sees coxswain's IP. The mTLS handshake
// still runs end-to-end over the relayed conn, so the relay stays protocol-blind.
func WithContextDialer(dial func(ctx context.Context, addr string) (net.Conn, error)) Option {
	return func(d *Dialer) { d.contextDialer = dial }
}

// NewDialer builds a Dialer. clientChainPEM is coxswain's controller certificate
// followed by the Fleet intermediate (so nodes can verify the chain);
// clientKeyPEM is its key; rootCAPEM is the root CA that node certificates
// must chain to.
func NewDialer(clientChainPEM, clientKeyPEM, rootCAPEM []byte, opts ...Option) (*Dialer, error) {
	cert, err := tls.X509KeyPair(clientChainPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("control: load controller cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCAPEM) {
		return nil, errors.New("control: no CA certificates in root PEM")
	}
	d := &Dialer{creds: credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	})}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Dial returns a control Client for the node at addr (host:port). The
// connection is lazy — it is established on the first RPC.
func (d *Dialer) Dial(addr string) (*Client, error) {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(d.creds)}
	if d.contextDialer != nil {
		dialOpts = append(dialOpts, grpc.WithContextDialer(d.contextDialer))
	}
	cc, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("control: dial %s: %w", addr, err)
	}
	return &Client{cc: cc, rpc: buoyv1.NewNodeControlClient(cc)}, nil
}
