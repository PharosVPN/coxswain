// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"
)

// leafValidity is the lifetime of an issued leaf certificate (DESIGN §4: node
// and relay certs are valid one year, then auto-rotated).
const leafValidity = 365 * 24 * time.Hour

// SignedCert is a certificate coxswain issued from a node-supplied CSR. coxswain never
// sees the private key — the node generated and kept it.
type SignedCert struct {
	Serial  string
	Cert    *x509.Certificate
	CertPEM []byte
}

// SignNodeCSR validates a buoy node's certificate request and signs it with
// the Fleet CA, yielding a one-year server certificate (DESIGN §5). The node
// keeps its private key; only the CSR crosses to coxswain.
//
// extraIPs and extraDNS are SANs coxswain adds on top of those in the CSR — coxswain
// pins the address it will dial rather than trusting the request alone.
func SignNodeCSR(fleet Authority, csrPEM []byte, extraIPs []net.IP, extraDNS []string) (SignedCert, error) {
	if fleet.Role != RoleFleet {
		return SignedCert{}, fmt.Errorf("SignNodeCSR: expected fleet CA, got %q", fleet.Role)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return SignedCert{}, errors.New("SignNodeCSR: not a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return SignedCert{}, fmt.Errorf("SignNodeCSR: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return SignedCert{}, fmt.Errorf("SignNodeCSR: CSR self-signature invalid: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return SignedCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append(append([]string{}, csr.DNSNames...), extraDNS...),
		IPAddresses:           append(append([]net.IP{}, csr.IPAddresses...), extraIPs...),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, fleet.Cert, csr.PublicKey, fleet.Key)
	if err != nil {
		return SignedCert{}, fmt.Errorf("SignNodeCSR: sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return SignedCert{}, err
	}
	return SignedCert{
		Serial:  serial.String(),
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// SignRelayCSR signs a remote beacon relay's certificate request with the
// Fleet CA (BUILD.md "Relay enrollment contract"). Unlike SignNodeCSR it takes
// only the CSR's public key: coxswain is the sole authority on a relay's identity,
// so it overrides the subject and EKUs rather than trust the request.
//
// The result is the pinned relay leaf — one Fleet-CA certificate carrying
// Organization "PharosVPN Relay" (coxswain's gRPC auth path keys delegation off
// it), both the ServerAuth and ClientAuth EKUs, and hostname as a SAN (the
// public client endpoint caravel verifies). The relay keeps its private key.
func SignRelayCSR(fleet Authority, csrPEM []byte, hostname string) (SignedCert, error) {
	if fleet.Role != RoleFleet {
		return SignedCert{}, fmt.Errorf("SignRelayCSR: expected fleet CA, got %q", fleet.Role)
	}
	if hostname == "" {
		return SignedCert{}, errors.New("SignRelayCSR: relay hostname is required")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return SignedCert{}, errors.New("SignRelayCSR: not a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return SignedCert{}, fmt.Errorf("SignRelayCSR: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return SignedCert{}, fmt.Errorf("SignRelayCSR: CSR self-signature invalid: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return SignedCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: relayOrg, Organization: []string{relayOrg}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, fleet.Cert, csr.PublicKey, fleet.Key)
	if err != nil {
		return SignedCert{}, fmt.Errorf("SignRelayCSR: sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return SignedCert{}, err
	}
	return SignedCert{
		Serial:  serial.String(),
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}
