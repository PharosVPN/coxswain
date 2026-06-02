// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package egress is coxswain's side of control-plane egress relaying (DESIGN
// §3, decision 19): it dials a relay over an outbound tunnel and reaches nodes
// through it, so a node — or anyone watching it — sees the relay's IP, never
// coxswain's. Both control channels (gRPC NodeControl, SSH) route through one
// DialContext, so neither leaks coxswain's location.
package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	bxegress "github.com/PharosVPN/relay/egress"
)

const dialTimeout = 10 * time.Second

// Tunnel is coxswain's outbound egress tunnel to a relay. It TLS-dials the
// relay, holds a yamux client session, and opens a substream per outbound dial.
// coxswain remains the dialer — zero inbound — exactly as on the ingress tunnel.
//
// Reconnection is lazy: a dead session is re-dialed on the next DialContext.
// That suits a control plane whose outages are survivable (decision 19, "no
// HA") — nodes keep serving from persisted state during a relay blip.
type Tunnel struct {
	relayAddr string
	dial      func(ctx context.Context, addr string) (net.Conn, error)

	mu   sync.Mutex
	sess *bxegress.ClientSession
}

// New returns a Tunnel that TLS-dials relayAddr (the relay's egress tunnel
// listener) with tlsCfg — coxswain's Fleet-CA client cert; the relay presents
// its relay cert, so the tunnel leg is mutually authenticated just like the
// ingress tunnel.
func New(relayAddr string, tlsCfg *tls.Config) *Tunnel {
	t := &Tunnel{relayAddr: relayAddr}
	t.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: tlsCfg}
		return d.DialContext(ctx, "tcp", addr)
	}
	return t
}

// DialContext dials a node addr (host:port) through the relay. Its signature
// matches net.Dialer.DialContext, so the SSH client can use it directly and the
// gRPC client wraps it for grpc.WithContextDialer — one chokepoint for both
// channels. network is informational; the relay always dials TCP to the node.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return bxegress.Open(ctx, t, addr)
}

// OpenStream satisfies bxegress.StreamOpener: it returns a substream to the
// relay, re-dialing the tunnel first if the session is down.
func (t *Tunnel) OpenStream(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil || t.sess.IsClosed() {
		if err := t.redialLocked(ctx); err != nil {
			return nil, err
		}
	}
	stream, err := t.sess.OpenStream(ctx)
	if err != nil {
		// The session may have died between the check and the open; re-dial once.
		if rerr := t.redialLocked(ctx); rerr != nil {
			return nil, rerr
		}
		return t.sess.OpenStream(ctx)
	}
	return stream, nil
}

func (t *Tunnel) redialLocked(ctx context.Context) error {
	if t.sess != nil {
		_ = t.sess.Close()
		t.sess = nil
	}
	conn, err := t.dial(ctx, t.relayAddr)
	if err != nil {
		return fmt.Errorf("egress: dial relay %s: %w", t.relayAddr, err)
	}
	sess, err := bxegress.NewClientSession(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	t.sess = sess
	return nil
}

// Close tears down the tunnel session. Idempotent.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess == nil {
		return nil
	}
	err := t.sess.Close()
	t.sess = nil
	return err
}
