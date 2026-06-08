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

// connectDisconnectCumulativeNode emits a PEER_CONNECTED carrying the peer's
// cumulative awg counters (connectRx/connectTx) then a PEER_DISCONNECTED carrying
// the later cumulative (disconnectRx/disconnectTx), then holds the stream open —
// the steady-state case the controller pairs into a per-session delta.
type connectDisconnectCumulativeNode struct {
	nodev1.UnimplementedNodeControlServer
	peer                                             string
	connectRx, connectTx, disconnectRx, disconnectTx int64
}

func (n connectDisconnectCumulativeNode) WatchEvents(_ *nodev1.WatchEventsRequest, stream grpc.ServerStreamingServer[nodev1.Event]) error {
	if err := stream.Send(&nodev1.Event{
		Type:           nodev1.EventType_EVENT_TYPE_PEER_CONNECTED,
		Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		PeerId:         n.peer,
		SourceEndpoint: "203.0.113.9:51820",
		RxBytes:        n.connectRx,
		TxBytes:        n.connectTx,
	}); err != nil {
		return err
	}
	if err := stream.Send(&nodev1.Event{
		Type:           nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED,
		Protocol:       nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		PeerId:         n.peer,
		SourceEndpoint: "203.0.113.9:51820",
		RxBytes:        n.disconnectRx,
		TxBytes:        n.disconnectTx,
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// recordingSink captures every event passed to Ingest, for asserting the
// persisted session events (the stream-lost disconnect, and the connect→
// disconnect byte pairing). Resolve is a no-op (the peer is left unresolved;
// these paths do not depend on resolution). SessionBytes mirrors the controller
// pairing (monitor.Store.SessionBytes) so the live plane's delta computation is
// exercised end-to-end: connect remembers the cumulative, disconnect deltas.
type recordingSink struct {
	mu     sync.Mutex
	events []monitor.Event
	open   map[string][2]uint64 // peer → {connectRxCum, connectTxCum}
}

func (s *recordingSink) Resolve(context.Context, string) monitor.Resolution {
	return monitor.Resolution{}
}

func (s *recordingSink) Ingest(ev monitor.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *recordingSink) SessionBytes(peerID, eventType string, rxCum, txCum uint64) (uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		s.open = map[string][2]uint64{}
	}
	switch eventType {
	case "connect":
		s.open[peerID] = [2]uint64{rxCum, txCum}
		return 0, 0
	case "disconnect":
		base, ok := s.open[peerID]
		delete(s.open, peerID)
		if !ok {
			return 0, 0
		}
		return sessionDelta(rxCum, base[0]), sessionDelta(txCum, base[1])
	default:
		return 0, 0
	}
}

// sessionDelta mirrors monitor.delta: current − connect, clamped to 0 on a
// counter reset.
func sessionDelta(current, connect uint64) uint64 {
	if current < connect {
		return 0
	}
	return current - connect
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

// TestDisconnectPersistsSessionBytes proves the CONTROLLER pairs the node's raw
// cumulative counters into a per-session delta: the node emits a connect at
// cumulative C1 and a disconnect at cumulative C2, and the controller persists
// (and fans to the hub) the delta C2−C1, not the raw cumulative. The connect row
// carries 0. This is the robust-bytes design — pairing on the controller, not an
// in-observer baseline.
func TestDisconnectPersistsSessionBytes(t *testing.T) {
	const peer = "peer-with-bytes"
	// Connect cumulative C1; disconnect cumulative C2; expected session delta.
	const c1Rx, c1Tx = 1_000_000, 2_000_000
	const c2Rx, c2Tx = 1_123_456, 2_654_321
	const wantRx, wantTx = c2Rx - c1Rx, c2Tx - c1Tx
	addr, dialer := startNodeServer(t, connectDisconnectCumulativeNode{
		peer: peer, connectRx: c1Rx, connectTx: c1Tx, disconnectRx: c2Rx, disconnectTx: c2Tx,
	})

	hub := NewHub()
	_, events := hub.Subscribe()
	sink := &recordingSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchNode(ctx, dialer, fleet.Node{ID: "nod_bytes", ControlAddr: addr}, hub, sink)

	// On the hub, the connect must carry 0 and the disconnect the computed delta.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-events:
			switch e.Type {
			case "PEER_CONNECTED":
				if e.RxBytes != 0 || e.TxBytes != 0 {
					t.Errorf("hub connect carried rx=%d tx=%d, want 0/0", e.RxBytes, e.TxBytes)
				}
				continue
			case "PEER_DISCONNECTED":
				if e.RxBytes != wantRx || e.TxBytes != wantTx {
					t.Errorf("hub disconnect delta rx=%d tx=%d, want %d/%d", e.RxBytes, e.TxBytes, wantRx, wantTx)
				}
			default:
				continue
			}
		case <-deadline:
			t.Fatal("timed out waiting for disconnect on the hub")
		}
		break
	}

	// The persisted disconnect must carry the delta; the connect row carries 0.
	deadline = time.After(5 * time.Second)
	for {
		var disc, conn *monitor.Event
		for _, ev := range sink.snapshot() {
			if ev.PeerID != peer {
				continue
			}
			e := ev
			switch ev.EventType {
			case "disconnect":
				disc = &e
			case "connect":
				conn = &e
			}
		}
		if disc != nil && conn != nil {
			if conn.RxBytes != 0 || conn.TxBytes != 0 {
				t.Errorf("persisted connect rx=%d tx=%d, want 0/0", conn.RxBytes, conn.TxBytes)
			}
			if disc.RxBytes != wantRx || disc.TxBytes != wantTx {
				t.Errorf("persisted disconnect delta rx=%d tx=%d, want %d/%d", disc.RxBytes, disc.TxBytes, wantRx, wantTx)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for persisted events; got: %+v", sink.snapshot())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestStreamDropPublishesDisconnectToHub: when a node's stream drops with a peer
// still connected, the synthetic close-out must ALSO fan to the live hub (not
// only the history sink), so the SSE/WS dashboard feed and the gRPC SIEM stream
// see the session close. The published event is a PEER_DISCONNECTED carrying
// reason "stream-lost" with the original peer's attribution.
func TestStreamDropPublishesDisconnectToHub(t *testing.T) {
	const peer = "peer-stays-open"
	addr, dialer := startNodeServer(t, connectThenDropNode{peer: peer})

	hub := NewHub()
	_, events := hub.Subscribe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// nil sink: persistence is irrelevant here — we assert the HUB publish.
	go WatchNode(ctx, dialer, fleet.Node{ID: "nod_drop", ControlAddr: addr}, hub, nil)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type != "PEER_DISCONNECTED" {
				continue // skip the initial PEER_CONNECTED
			}
			if e.PeerID != peer {
				t.Errorf("disconnect peer = %q want %q", e.PeerID, peer)
			}
			if e.Reason != "stream-lost" {
				t.Errorf("disconnect reason = %q want stream-lost", e.Reason)
			}
			if e.NodeID != "nod_drop" {
				t.Errorf("disconnect node = %q want nod_drop", e.NodeID)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for stream-lost disconnect on the hub")
		}
	}
}
