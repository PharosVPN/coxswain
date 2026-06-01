// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package control is coxswain's outbound gRPC control plane: it dials each buoy
// node over mTLS and drives the NodeControl service (DESIGN §6, §7).
package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Dialer opens mTLS gRPC connections to buoy nodes. It is built once from
// coxswain's controller certificate and reused for every node.
type Dialer struct {
	creds credentials.TransportCredentials
}

// NewDialer builds a Dialer. clientChainPEM is coxswain's controller certificate
// followed by the Fleet intermediate (so nodes can verify the chain);
// clientKeyPEM is its key; rootCAPEM is the root CA that node certificates
// must chain to.
func NewDialer(clientChainPEM, clientKeyPEM, rootCAPEM []byte) (*Dialer, error) {
	cert, err := tls.X509KeyPair(clientChainPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("control: load controller cert: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCAPEM) {
		return nil, errors.New("control: no CA certificates in root PEM")
	}
	return &Dialer{creds: credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
	})}, nil
}

// Dial returns a control Client for the node at addr (host:port). The
// connection is lazy — it is established on the first RPC.
func (d *Dialer) Dial(addr string) (*Client, error) {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(d.creds))
	if err != nil {
		return nil, fmt.Errorf("control: dial %s: %w", addr, err)
	}
	return &Client{cc: cc, rpc: buoyv1.NewNodeControlClient(cc)}, nil
}
