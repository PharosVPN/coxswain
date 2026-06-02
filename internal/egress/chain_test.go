// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	bxegress "github.com/PharosVPN/beacon/egress"
)

// testTLS mints a throwaway CA and one dual-EKU leaf (server+client, SAN
// 127.0.0.1), mirroring a relay's Fleet-CA cert. Both relays present it as a
// server and coxswain presents it as a client, all verified against the CA.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	server = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	client = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	return server, client
}

// startTLSRelay runs a beacon egress relay behind a mutual-TLS listener on
// 127.0.0.1 and returns its address.
func startTLSRelay(t *testing.T, ctx context.Context, serverTLS *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tln := tls.NewListener(ln, serverTLS)
	nodeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	go func() { _ = bxegress.RunRelay(ctx, tln, nodeDial, nil) }()
	return ln.Addr().String()
}

// TestChainTwoHops proves a two-relay chain carries traffic end to end with
// mutual TLS at each hop: coxswain → relay1 → relay2 → backend, with the
// relay2 leg nested inside the relay1 tunnel.
func TestChainTwoHops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := newEcho(t)
	serverTLS, clientTLS := testTLS(t)
	relay1 := startTLSRelay(t, ctx, serverTLS)
	relay2 := startTLSRelay(t, ctx, serverTLS)

	chain, err := NewChain([]Hop{
		{Endpoint: relay1, TLS: clientTLS},
		{Endpoint: relay2, TLS: clientTLS},
	})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	defer chain.Close()

	conn, err := chain.DialContext(ctx, "tcp", backend)
	if err != nil {
		t.Fatalf("chain DialContext: %v", err)
	}
	defer conn.Close()
	echoOnce(t, conn, "through two relays")
}

// TestNewChainRejectsEmpty guards the precondition.
func TestNewChainRejectsEmpty(t *testing.T) {
	if _, err := NewChain(nil); err == nil {
		t.Fatal("NewChain(nil) = nil error, want rejection")
	}
}
