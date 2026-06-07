// SPDX-License-Identifier: Apache-2.0
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

// SignNodeCSR validates a node's certificate request and signs it with
// the Fleet CA, yielding a one-year server certificate (DESIGN §5). The node
// keeps its private key; only the CSR crosses to coxswain.
//
// coxswain is the sole authority on a node's identity: it pins the SANs to the
// address it will dial (extraIPs / extraDNS) and the Subject to a value it
// controls, ignoring both the SANs and the Subject in the CSR. A compromised
// node therefore cannot mint a cert carrying another node's address or an
// arbitrary hostname — node mTLS keys off the Fleet-CA chain plus this pinned
// SAN, which coxswain verifies when it dials the node (internal/control/dial.go),
// not off the Subject. Only the CSR's public key survives (the node keeps its
// private key).
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
	// Pin the SANs to the address coxswain dials; the CSR's own SANs are
	// discarded so a node cannot assert an identity it was not granted.
	dnsNames := append([]string{}, extraDNS...)
	ipAddrs := append([]net.IP{}, extraIPs...)

	// Derive a controller-controlled Subject CN from the pinned identity rather
	// than trusting csr.Subject.
	cn := "PharosVPN Node"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else if len(ipAddrs) > 0 {
		cn = ipAddrs[0].String()
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{nodeOrg}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
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

// SignRelayCSR signs a remote relay's certificate request with the
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
