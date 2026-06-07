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
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
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

// startFakeNode brings up an mTLS NodeControl server and a matching control
// Dialer, returning the server's address.
func startFakeNode(t *testing.T) (addr string, dialer *control.Dialer) {
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
	nodev1.RegisterNodeControlServer(srv, fakeNode{})

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
