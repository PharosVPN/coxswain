// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

// Hop is one relay in an egress chain: the relay's `relay egress` endpoint and
// the TLS config coxswain authenticates to it with (its controller cert + the
// roots that verify the relay). NewChain sets ServerName per hop.
type Hop struct {
	Endpoint string
	TLS      *tls.Config
}

// NewChain builds an egress tunnel through hops in order: coxswain → hops[0] →
// hops[1] → … → hops[N-1] → node (DESIGN §3, decision 19, ladder step 2). Each
// hop's TLS connection is dialed THROUGH the previous hop's tunnel, so the chain
// nests: the first relay sees coxswain's address but only learns the next hop;
// the last relay reaches the node but its TCP peer is the previous relay, not
// coxswain. Hence no single relay sees both coxswain's address and the node's.
//
// The returned Tunnel's DialContext routes a node dial through the whole chain;
// it reconnects lazily hop by hop. A single-hop chain is exactly New's tunnel.
func NewChain(hops []Hop) (*Tunnel, error) {
	if len(hops) == 0 {
		return nil, errors.New("egress: chain needs at least one hop")
	}
	var prev *Tunnel
	for i := range hops {
		hop := hops[i]
		host, _, err := net.SplitHostPort(hop.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("egress: hop %d endpoint %q: %w", i, hop.Endpoint, err)
		}
		if hop.TLS == nil {
			return nil, fmt.Errorf("egress: hop %d (%s) has no TLS config", i, hop.Endpoint)
		}
		cfg := hop.TLS.Clone()
		cfg.ServerName = host // verify this relay's cert SAN; the dial host is opaque to tls.Client

		prevTun := prev
		t := &Tunnel{relayAddr: hop.Endpoint}
		t.dial = func(ctx context.Context, addr string) (net.Conn, error) {
			raw, err := dialHop(ctx, prevTun, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("egress: tls handshake to %s: %w", addr, err)
			}
			return tlsConn, nil
		}
		prev = t
	}
	return prev, nil
}

// dialHop dials addr directly for the first hop, or tunnels through prev for the
// deeper hops (a CONNECT substream on prev's relay to addr).
func dialHop(ctx context.Context, prev *Tunnel, addr string) (net.Conn, error) {
	if prev == nil {
		return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	}
	return prev.DialContext(ctx, "tcp", addr)
}
