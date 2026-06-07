// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// makeCSR generates a node keypair and a PEM-encoded CSR, as node would on the
// node. The private key never leaves; only csrPEM is returned.
func makeCSR(t *testing.T, cn string) []byte {
	t.Helper()
	return makeCSRWithSANs(t, cn, []string{cn + ".fleet.internal"}, nil)
}

// makeCSRWithSANs builds a CSR carrying caller-chosen SANs — used to assert that
// coxswain discards node-supplied SANs when it signs.
func makeCSRWithSANs(t *testing.T, cn string, dnsNames []string, ipAddrs []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignNodeCSRChains(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	signed, err := pki.SignNodeCSR(b.Fleet, makeCSR(t, "node-ams-1"),
		[]net.IP{net.ParseIP("203.0.113.7")}, nil)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(b.Root.Cert)
	inter := x509.NewCertPool()
	inter.AddCert(b.Fleet.Cert)
	if _, err := signed.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("signed cert does not chain root->fleet->leaf: %v", err)
	}

	if len(signed.Cert.IPAddresses) != 1 || !signed.Cert.IPAddresses[0].Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("pinned IP SAN missing: %v", signed.Cert.IPAddresses)
	}
	// The CSR's own DNS SAN (node-ams-1.fleet.internal) is node-controlled and
	// must NOT survive — coxswain pinned only the dial IP, no extra DNS.
	if len(signed.Cert.DNSNames) != 0 {
		t.Errorf("CSR DNS SAN leaked onto the certificate: %v", signed.Cert.DNSNames)
	}
	// Subject is controller-controlled: CN from the pinned identity, O=PharosVPN.
	if cn := signed.Cert.Subject.CommonName; cn != "203.0.113.7" {
		t.Errorf("subject CN: got %q want 203.0.113.7 (pinned IP)", cn)
	}
	if orgs := signed.Cert.Subject.Organization; len(orgs) != 1 || orgs[0] != "PharosVPN Node" {
		t.Errorf("subject O: got %v want [PharosVPN Node]", orgs)
	}
}

// TestSignNodeCSRDropsRogueSANs is the security regression test: a compromised
// node submitting a CSR with another node's address / a forged hostname must not
// get a cert carrying those SANs. coxswain pins only the address it will dial.
func TestSignNodeCSRDropsRogueSANs(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	// Node forges a DNS SAN and an IP SAN for a host it does not own.
	rogue := makeCSRWithSANs(t, "node-victim",
		[]string{"evil.example"}, []net.IP{net.ParseIP("8.8.8.8")})

	// coxswain pins the real dial address (the node's actual hostname).
	signed, err := pki.SignNodeCSR(b.Fleet, rogue, nil, []string{"node-ams-1.fleet.internal"})
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}

	for _, dns := range signed.Cert.DNSNames {
		if dns == "evil.example" {
			t.Errorf("rogue DNS SAN evil.example leaked onto the cert: %v", signed.Cert.DNSNames)
		}
	}
	for _, ip := range signed.Cert.IPAddresses {
		if ip.Equal(net.ParseIP("8.8.8.8")) {
			t.Errorf("rogue IP SAN 8.8.8.8 leaked onto the cert: %v", signed.Cert.IPAddresses)
		}
	}
	// The controller-pinned SAN is present and is the only DNS SAN.
	if len(signed.Cert.DNSNames) != 1 || signed.Cert.DNSNames[0] != "node-ams-1.fleet.internal" {
		t.Errorf("pinned DNS SAN: got %v want [node-ams-1.fleet.internal]", signed.Cert.DNSNames)
	}
	if len(signed.Cert.IPAddresses) != 0 {
		t.Errorf("no IP SAN was pinned, but cert carries: %v", signed.Cert.IPAddresses)
	}
	// CN comes from the pinned identity, not the CSR's "node-victim".
	if cn := signed.Cert.Subject.CommonName; cn != "node-ams-1.fleet.internal" {
		t.Errorf("subject CN: got %q want node-ams-1.fleet.internal (pinned)", cn)
	}
}

// TestSignNodeCSRDefaultSubject covers the fallback CN when coxswain pins no
// SANs at all (no extras) — the Subject is still controller-controlled.
func TestSignNodeCSRDefaultSubject(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	signed, err := pki.SignNodeCSR(b.Fleet, makeCSR(t, "node-attacker"), nil, nil)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	if cn := signed.Cert.Subject.CommonName; cn != "PharosVPN Node" {
		t.Errorf("subject CN: got %q want PharosVPN Node (default)", cn)
	}
	if len(signed.Cert.DNSNames) != 0 || len(signed.Cert.IPAddresses) != 0 {
		t.Errorf("no SANs pinned but cert carries dns=%v ip=%v",
			signed.Cert.DNSNames, signed.Cert.IPAddresses)
	}
}

func TestSignRelayCSR(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	signed, err := pki.SignRelayCSR(b.Fleet, makeCSR(t, "ignored-subject"), "relay.example.net")
	if err != nil {
		t.Fatalf("SignRelayCSR: %v", err)
	}

	// coxswain dictates the relay identity — the CSR's subject is ignored.
	if cn := signed.Cert.Subject.CommonName; cn != "PharosVPN Relay" {
		t.Errorf("subject CN: got %q want PharosVPN Relay", cn)
	}
	if orgs := signed.Cert.Subject.Organization; len(orgs) != 1 || orgs[0] != "PharosVPN Relay" {
		t.Errorf("subject O: got %v want [PharosVPN Relay]", orgs)
	}
	// One dual-EKU leaf — server (public + tunnel listeners) and client
	// (backend gRPC leg).
	hasServer, hasClient := false, false
	for _, eku := range signed.Cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		}
	}
	if !hasServer || !hasClient {
		t.Errorf("EKU: server=%t client=%t, want both", hasServer, hasClient)
	}
	// The hostname coxswain passed — not the CSR's — is the SAN.
	if len(signed.Cert.DNSNames) != 1 || signed.Cert.DNSNames[0] != "relay.example.net" {
		t.Errorf("DNS SAN: got %v want [relay.example.net]", signed.Cert.DNSNames)
	}

	roots := x509.NewCertPool()
	roots.AddCert(b.Root.Cert)
	inter := x509.NewCertPool()
	inter.AddCert(b.Fleet.Cert)
	if _, err := signed.Cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("relay cert does not chain root->fleet->leaf: %v", err)
	}

	// An IP hostname lands as an IP SAN, not a DNS SAN.
	ipSigned, err := pki.SignRelayCSR(b.Fleet, makeCSR(t, "x"), "198.51.100.9")
	if err != nil {
		t.Fatalf("SignRelayCSR (ip): %v", err)
	}
	if len(ipSigned.Cert.IPAddresses) != 1 || len(ipSigned.Cert.DNSNames) != 0 {
		t.Errorf("IP hostname SAN: ips=%v dns=%v", ipSigned.Cert.IPAddresses, ipSigned.Cert.DNSNames)
	}
}

func TestSignRelayCSRRejectsBadInput(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if _, err := pki.SignRelayCSR(b.Root, makeCSR(t, "x"), "h"); err == nil {
		t.Error("expected SignRelayCSR to reject a non-Fleet CA")
	}
	if _, err := pki.SignRelayCSR(b.Fleet, makeCSR(t, "x"), ""); err == nil {
		t.Error("expected SignRelayCSR to reject an empty hostname")
	}
	if _, err := pki.SignRelayCSR(b.Fleet, []byte("not a pem"), "h"); err == nil {
		t.Error("expected SignRelayCSR to reject non-PEM input")
	}
}

func TestSignNodeCSRRejectsNonFleetCA(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	csr := makeCSR(t, "x")
	if _, err := pki.SignNodeCSR(b.Root, csr, nil, nil); err == nil {
		t.Error("expected SignNodeCSR to reject the root CA")
	}
	if _, err := pki.SignNodeCSR(b.Device, csr, nil, nil); err == nil {
		t.Error("expected SignNodeCSR to reject the device CA")
	}
}

func TestSignNodeCSRRejectsGarbage(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if _, err := pki.SignNodeCSR(b.Fleet, []byte("not a pem"), nil, nil); err == nil {
		t.Error("expected SignNodeCSR to reject non-PEM input")
	}
}

func TestRecordNodeCert(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO nodes (id, name, region) VALUES ('nod_test', 'ams-1', 'eu')`); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	signed, err := pki.SignNodeCSR(b.Fleet, makeCSR(t, "node-ams-1"), nil, nil)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}

	id, err := pki.RecordNodeCert(ctx, conn, "nod_test", signed)
	if err != nil {
		t.Fatalf("RecordNodeCert: %v", err)
	}

	var serial string
	if err := conn.QueryRowContext(ctx,
		`SELECT serial FROM node_certs WHERE id = ?`, id).Scan(&serial); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if serial != signed.Serial {
		t.Errorf("serial: got %q want %q", serial, signed.Serial)
	}
}
