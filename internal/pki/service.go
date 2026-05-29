// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"
)

// Service-certificate roles (the `service_certs` table) — coxswain's certs for the
// beacon relay tier (DESIGN §2, M6b-2).
const (
	// ServiceGRPC is coxswain's account/sync gRPC server cert. The relay dials it
	// with SNI "coxswain-grpc".
	ServiceGRPC = "grpc"
	// ServiceRelay is the relay's single dual-EKU Fleet-CA leaf, also used as
	// coxswain's client cert on the remote reverse-tunnel leg (coxswain/BUILD.md).
	ServiceRelay = "relay"

	// relayOrg is the delegation Organization coxswain's auth path keys off.
	relayOrg = "PharosVPN Relay"
	// GRPCServerName is the CN/SAN of coxswain's gRPC-leg leaf; the relay verifies
	// coxswain's backend cert against it (relay.Config.BackendServerName).
	GRPCServerName = "coxswain-grpc"
)

// ServiceCert is a stored service certificate and its key. coxswain holds both —
// these are coxswain's own / the embedded relay's identities.
type ServiceCert struct {
	Role    string
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// EnsureServiceCert returns coxswain's service certificate for the given role,
// issuing it off the Fleet CA on first call.
func EnsureServiceCert(ctx context.Context, db *sql.DB, fleet Authority, role string) (ServiceCert, error) {
	var certPEM, keyPEM string
	err := db.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem FROM service_certs WHERE role = ?`, role,
	).Scan(&certPEM, &keyPEM)
	if err == nil {
		cert, derr := decodeCert([]byte(certPEM))
		if derr != nil {
			return ServiceCert{}, fmt.Errorf("decode %s service cert: %w", role, derr)
		}
		return ServiceCert{Role: role, Cert: cert, CertPEM: []byte(certPEM), KeyPEM: []byte(keyPEM)}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ServiceCert{}, err
	}

	sc, err := issueServiceCert(fleet, role)
	if err != nil {
		return ServiceCert{}, err
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO service_certs (role, cert_pem, key_pem, serial, not_after)
		 VALUES (?, ?, ?, ?, ?)`,
		sc.Role, string(sc.CertPEM), string(sc.KeyPEM), sc.Cert.SerialNumber.String(), sc.Cert.NotAfter,
	); err != nil {
		return ServiceCert{}, fmt.Errorf("store %s service cert: %w", role, err)
	}
	return sc, nil
}

func issueServiceCert(fleet Authority, role string) (ServiceCert, error) {
	if fleet.Role != RoleFleet {
		return ServiceCert{}, fmt.Errorf("issueServiceCert: expected fleet CA, got %q", fleet.Role)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ServiceCert{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return ServiceCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	switch role {
	case ServiceGRPC:
		tmpl.Subject = pkix.Name{CommonName: GRPCServerName, Organization: []string{"PharosVPN"}}
		tmpl.DNSNames = []string{GRPCServerName}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case ServiceRelay:
		// One dual-EKU leaf: public listener (server), backend + tunnel
		// (client). Organization carries the delegation marker.
		tmpl.Subject = pkix.Name{CommonName: relayOrg, Organization: []string{relayOrg}}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return ServiceCert{}, fmt.Errorf("issueServiceCert: unknown role %q", role)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, fleet.Cert, &key.PublicKey, fleet.Key)
	if err != nil {
		return ServiceCert{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ServiceCert{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ServiceCert{}, err
	}
	return ServiceCert{
		Role:    role,
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
