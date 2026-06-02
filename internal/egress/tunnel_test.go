// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	bxegress "github.com/PharosVPN/relay/egress"
)

// newEcho starts a TCP echo backend — the stand-in node the relay dials.
func newEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// startRelay runs a relay egress relay on a plain TCP listener (the test
// skips TLS by injecting a plain dialer into the Tunnel) and returns its addr.
func startRelay(t *testing.T, ctx context.Context) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	nodeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	go func() { _ = bxegress.RunRelay(ctx, ln, nodeDial, nil) }()
	return ln.Addr().String()
}

// plainTunnel builds a Tunnel that skips TLS — for tests only; production New()
// installs the TLS dialer.
func plainTunnel(relayAddr string) *Tunnel {
	t := New(relayAddr, nil)
	t.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	return t
}

func echoOnce(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, []byte(msg)) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestTunnelDialThroughRelay proves coxswain's Tunnel.DialContext reaches a node
// through the relay end to end — the node sees the relay, not coxswain.
func TestTunnelDialThroughRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := newEcho(t)
	relay := startRelay(t, ctx)

	tun := plainTunnel(relay)
	defer tun.Close()

	conn, err := tun.DialContext(ctx, "tcp", backend)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	echoOnce(t, conn, "via the egress relay")
}

// TestTunnelLazyReconnect proves a dialed-again Tunnel re-establishes its
// session after it was torn down — the lazy-reconnect path.
func TestTunnelLazyReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := newEcho(t)
	relay := startRelay(t, ctx)

	tun := plainTunnel(relay)
	defer tun.Close()

	c1, err := tun.DialContext(ctx, "tcp", backend)
	if err != nil {
		t.Fatalf("first DialContext: %v", err)
	}
	echoOnce(t, c1, "first")
	_ = c1.Close()

	// Tear the session down out from under the Tunnel; the next dial must
	// transparently re-establish it.
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c2, err := tun.DialContext(ctx, "tcp", backend)
	if err != nil {
		t.Fatalf("DialContext after teardown (lazy reconnect failed): %v", err)
	}
	defer c2.Close()
	echoOnce(t, c2, "after reconnect")
}
