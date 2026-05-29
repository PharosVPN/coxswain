// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package relayhost_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/db"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/relayhost"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const passphrase = "the-account-passphrase"

// TestEmbeddedRelayRoundTrip drives the full embedded data path: a caravel-like
// client presenting a Device-CA leaf dials the in-process relay's public mTLS
// listener, and the relay forwards the AccountSync RPC to coxswain's gRPC server
// over the in-memory pipe — the same auth path the remote tunnel uses.
func TestEmbeddedRelayRoundTrip(t *testing.T) {
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
	grpcCert, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceGRPC)
	if err != nil {
		t.Fatalf("EnsureServiceCert grpc: %v", err)
	}
	relayCert, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceRelay)
	if err != nil {
		t.Fatalf("EnsureServiceCert relay: %v", err)
	}

	// Seed an account so Authenticate has something to verify.
	hash, err := auth.HashPassword(passphrase)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := account.CreateUser(ctx, conn, account.User{
		Email: "user@example.com", Role: account.RoleUser, PasswordHash: hash,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := relayhost.AccountServer(conn, grpcCert, bundle.Fleet.CertPEM)
	if err != nil {
		t.Fatalf("AccountServer: %v", err)
	}
	emb, err := relayhost.StartEmbedded(srv, relayhost.EmbeddedConfig{
		ClientListen: "127.0.0.1:0",
		RelayCert:    relayCert,
		DeviceCAPEM:  bundle.Device.CertPEM,
		FleetCAPEM:   bundle.Fleet.CertPEM,
	})
	if err != nil {
		t.Fatalf("StartEmbedded: %v", err)
	}
	t.Cleanup(emb.Stop)

	// A caravel client: a Device-CA leaf, trusting the relay's Fleet-CA leaf.
	clientTLS := deviceClientTLS(t, bundle)
	cc, err := grpc.NewClient(emb.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { cc.Close() })
	client := accountv1.NewAccountSyncClient(cc)

	resp, err := client.Authenticate(ctx, &accountv1.AuthenticateRequest{
		Email: "user@example.com", Password: passphrase,
	})
	if err != nil {
		t.Fatalf("Authenticate through relay: %v", err)
	}
	if resp.GetSessionToken() == "" {
		t.Error("Authenticate returned an empty session token")
	}

	if _, err := client.Authenticate(ctx, &accountv1.AuthenticateRequest{
		Email: "user@example.com", Password: "wrong",
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad password through relay: got %v want Unauthenticated", err)
	}
}

// TestRunRemoteStopsOnContextCancel checks that the remote reverse-tunnel
// dialer reconnects against an unreachable beacon and unwinds cleanly when its
// context is cancelled — coxswain's shutdown path must not hang on a dead relay.
func TestRunRemoteStopsOnContextCancel(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	bundle, _, err := pki.EnsureCA(context.Background(), conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	relayCert, err := pki.EnsureServiceCert(context.Background(), conn, bundle.Fleet, pki.ServiceRelay)
	if err != nil {
		t.Fatalf("EnsureServiceCert relay: %v", err)
	}

	srv := grpc.NewServer()
	t.Cleanup(srv.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		// 127.0.0.1:1 is unreachable, so the dialer stays in its retry loop.
		done <- relayhost.RunRemote(ctx, srv, "127.0.0.1:1", relayCert, bundle.Fleet.CertPEM)
	}()

	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("RunRemote: got %v want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunRemote did not return after context cancel")
	}
}

// deviceClientTLS mints a Device-CA leaf and returns a client TLS config that
// presents it and pins the Fleet CA for verifying the relay.
func deviceClientTLS(t *testing.T, bundle pki.Bundle) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "device-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, bundle.Device.Cert, &key.PublicKey, bundle.Device.Key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.Fleet.CertPEM) {
		t.Fatal("append Fleet CA")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        mustParse(t, der),
		}},
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}
