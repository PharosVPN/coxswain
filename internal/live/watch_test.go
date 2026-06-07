// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package live

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/monitor"
	"github.com/PharosVPN/coxswain/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// fakeNode streams a fixed burst of events, then holds the stream open.
type fakeNode struct {
	nodev1.UnimplementedNodeControlServer
}

func (fakeNode) WatchEvents(_ *nodev1.WatchEventsRequest, stream grpc.ServerStreamingServer[nodev1.Event]) error {
	for i := 0; i < 3; i++ {
		if err := stream.Send(&nodev1.Event{
			Type:    nodev1.EventType_EVENT_TYPE_HANDSHAKE_UP,
			Message: "event",
		}); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// connectThenDropNode emits a single PEER_CONNECTED for one peer, then returns
// from WatchEvents (the stream drops) without ever sending the matching
// disconnect — exactly the node-restart / lost-stream case LOW-14 closes out.
type connectThenDropNode struct {
	nodev1.UnimplementedNodeControlServer
	peer string
}

func (n connectThenDropNode) WatchEvents(_ *nodev1.WatchEventsRequest, stream grpc.ServerStreamingServer[nodev1.Event]) error {
	return stream.Send(&nodev1.Event{
		Type:           nodev1.EventType_EVENT_TYPE_PEER_CONNECTED,
		Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		PeerId:         n.peer,
		SourceEndpoint: "203.0.113.9:51820",
	})
}

// recordingSink captures every event passed to Ingest, for asserting the
// synthetic stream-lost disconnect is persisted. Resolve is a no-op (the peer
// is left unresolved; the close-out path does not depend on resolution).
type recordingSink struct {
	mu     sync.Mutex
	events []monitor.Event
}

func (s *recordingSink) Resolve(context.Context, string) monitor.Resolution {
	return monitor.Resolution{}
}

func (s *recordingSink) Ingest(ev monitor.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *recordingSink) snapshot() []monitor.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]monitor.Event, len(s.events))
	copy(out, s.events)
	return out
}

// startFakeNode brings up an mTLS NodeControl server and a matching control
// Dialer, returning the server's address.
func startFakeNode(t *testing.T) (addr string, dialer *control.Dialer) {
	t.Helper()
	return startNodeServer(t, fakeNode{})
}

// startNodeServer brings up an mTLS NodeControl server registered with the given
// implementation, plus a matching control Dialer.
func startNodeServer(t *testing.T, impl nodev1.NodeControlServer) (addr string, dialer *control.Dialer) {
	t.Helper()
	ctx := context.Background()

	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	controllerCert, _, err := pki.EnsureControllerCert(ctx, conn, bundle.Fleet)
	if err != nil {
		t.Fatalf("EnsureControllerCert: %v", err)
	}

	// Node server certificate signed off the Fleet CA, valid for localhost.
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node-test"}}, nodeKey)
	if err != nil {
		t.Fatalf("node CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	signed, err := pki.SignNodeCSR(bundle.Fleet, csrPEM, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	serverCert, err := tls.X509KeyPair(
		joinPEM(signed.CertPEM, bundle.Fleet.CertPEM),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER}))
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(bundle.Root.CertPEM)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	})))
	nodev1.RegisterNodeControlServer(srv, impl)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(lis) //nolint:errcheck // returns on Stop
	t.Cleanup(srv.Stop)

	dialer, err = control.NewDialer(
		joinPEM(controllerCert.CertPEM, bundle.Fleet.CertPEM),
		controllerCert.KeyPEM, bundle.Root.CertPEM)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return lis.Addr().String(), dialer
}

func joinPEM(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

func TestWatchNodePublishesEvents(t *testing.T) {
	addr, dialer := startFakeNode(t)

	hub := NewHub()
	_, events := hub.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchNode(ctx, dialer, fleet.Node{ID: "nod_x", ControlAddr: addr}, hub, nil)

	for i := 0; i < 3; i++ {
		select {
		case e := <-events:
			if e.NodeID != "nod_x" || e.Type != "HANDSHAKE_UP" {
				t.Errorf("event %d: got %+v", i, e)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for event %d", i)
		}
	}
}

// TestStreamDropClosesOpenSessions is LOW-14: when a node's WatchEvents stream
// drops with a peer still connected (no disconnect sent), the controller must
// persist a synthetic, attributed disconnect so the session is not left open in
// the history forever.
func TestStreamDropClosesOpenSessions(t *testing.T) {
	const peer = "peer-stays-open"
	addr, dialer := startNodeServer(t, connectThenDropNode{peer: peer})

	hub := NewHub()
	sink := &recordingSink{}

	// Cancel as soon as we observe the close-out, so WatchNode's reconnect loop
	// does not run forever.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchNode(ctx, dialer, fleet.Node{ID: "nod_drop", ControlAddr: addr}, hub, sink)

	deadline := time.After(5 * time.Second)
	for {
		var disconnect *monitor.Event
		for _, ev := range sink.snapshot() {
			if ev.EventType == "disconnect" && ev.PeerID == peer {
				e := ev
				disconnect = &e
				break
			}
		}
		if disconnect != nil {
			if disconnect.Reason != "stream-lost" {
				t.Errorf("synthetic disconnect reason = %q want %q", disconnect.Reason, "stream-lost")
			}
			if disconnect.NodeID != "nod_drop" {
				t.Errorf("synthetic disconnect node = %q want nod_drop", disconnect.NodeID)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for synthetic disconnect; got events: %+v", sink.snapshot())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
