// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki_test

import (
	"crypto/x509"
	"testing"

	"github.com/PharosVPN/coxswain/internal/pki"
)

func TestIssueDeviceCertChainsAndClientAuth(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	dc, err := pki.IssueDeviceCert(b.Device, "you@pharos")
	if err != nil {
		t.Fatalf("IssueDeviceCert: %v", err)
	}
	if len(dc.KeyPEM) == 0 {
		t.Fatal("device cert has no private key (manual bundle must carry it)")
	}

	// The leaf must verify against the Device CA — that is exactly what the
	// relay's ClientCAs pool checks in the mTLS handshake.
	roots := x509.NewCertPool()
	roots.AddCert(b.Device.Cert)
	if _, err := dc.Cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("device leaf does not chain to Device CA with ClientAuth: %v", err)
	}

	// It must NOT chain to the Fleet CA (devices are a separate trust domain).
	fleetRoots := x509.NewCertPool()
	fleetRoots.AddCert(b.Fleet.Cert)
	if _, err := dc.Cert.Verify(x509.VerifyOptions{Roots: fleetRoots}); err == nil {
		t.Fatal("device leaf must not chain to the Fleet CA")
	}

	if dc.Cert.Subject.CommonName != "you@pharos" {
		t.Fatalf("CN = %q, want the label", dc.Cert.Subject.CommonName)
	}
}

func TestIssueDeviceCertRejectsNonDeviceCA(t *testing.T) {
	b, err := pki.GenerateBundle()
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if _, err := pki.IssueDeviceCert(b.Fleet, "x"); err == nil {
		t.Fatal("expected IssueDeviceCert to reject the Fleet CA")
	}
}
