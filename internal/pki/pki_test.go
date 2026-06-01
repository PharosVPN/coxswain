// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki_test

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/pki"
)

func TestGenerateBundleChains(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(b.Root.Cert)

	for _, leaf := range []pki.Authority{b.Fleet, b.Device} {
		if !leaf.Cert.IsCA {
			t.Errorf("%s: expected IsCA", leaf.Role)
		}
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Errorf("%s does not chain to root: %v", leaf.Role, err)
		}
	}
	if !b.Root.Cert.NotAfter.After(b.Fleet.Cert.NotAfter) {
		t.Error("root should outlive the fleet intermediate")
	}
}

func TestEnsureCAIdempotent(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	ctx := context.Background()
	first, created, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	if !created {
		t.Fatal("first EnsureCA: expected created=true")
	}

	second, created, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if created {
		t.Fatal("second EnsureCA: expected created=false")
	}
	if first.Root.Fingerprint() != second.Root.Fingerprint() {
		t.Error("root fingerprint changed across calls")
	}
	if first.Fleet.Fingerprint() != second.Fleet.Fingerprint() {
		t.Error("fleet fingerprint changed across calls")
	}
}
