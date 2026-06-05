// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki_test

import (
	"context"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// TestEnsureServiceCertRelaySAN guards the embedded relay's client-facing leaf:
// it must always carry localhost, gain a requested public host/IP SAN (so a
// remote caravel device that dials the public endpoint can verify it), re-mint
// when a stored cert predates that SAN, and stay stable once it is covered.
func TestEnsureServiceCertRelaySAN(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ctx := context.Background()
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	// First issue with no extra SAN — localhost only, no public IP.
	c1, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceRelay)
	if err != nil {
		t.Fatalf("EnsureServiceCert: %v", err)
	}
	if !hasIPSAN(c1.Cert, "127.0.0.1") {
		t.Error("relay cert missing localhost SAN")
	}
	if hasIPSAN(c1.Cert, "203.0.113.9") {
		t.Error("relay cert has a public SAN before one was requested")
	}

	// Re-request with a public IP SAN — must re-mint (new serial) to include it,
	// without dropping localhost.
	c2, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceRelay, "203.0.113.9")
	if err != nil {
		t.Fatalf("EnsureServiceCert+SAN: %v", err)
	}
	if !hasIPSAN(c2.Cert, "203.0.113.9") {
		t.Fatalf("relay cert missing requested public SAN: %v", c2.Cert.IPAddresses)
	}
	if !hasIPSAN(c2.Cert, "127.0.0.1") {
		t.Error("re-mint dropped the localhost SAN")
	}
	if c1.Cert.SerialNumber.Cmp(c2.Cert.SerialNumber) == 0 {
		t.Error("expected a re-mint (new serial) when a SAN was added")
	}

	// Idempotent once the SAN is covered — same cert, no churn.
	c3, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceRelay, "203.0.113.9")
	if err != nil {
		t.Fatalf("EnsureServiceCert idempotent: %v", err)
	}
	if c2.Cert.SerialNumber.Cmp(c3.Cert.SerialNumber) != 0 {
		t.Error("expected no re-mint when the SAN is already covered")
	}
}

func hasIPSAN(cert *x509.Certificate, ip string) bool {
	want := net.ParseIP(ip)
	for _, got := range cert.IPAddresses {
		if got.Equal(want) {
			return true
		}
	}
	return false
}
