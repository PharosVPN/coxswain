// SPDX-License-Identifier: Apache-2.0
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
	"time"
)

// ControllerCert is coxswain's own client certificate, presented when coxswain dials a
// node's mTLS control port (DESIGN §4). coxswain legitimately holds this
// private key — it is coxswain's own identity.
type ControllerCert struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
	Serial  string
}

// EnsureControllerCert returns coxswain's controller certificate, issuing one off
// the Fleet CA on first call. The boolean reports whether one was created.
func EnsureControllerCert(ctx context.Context, db *sql.DB, fleet Authority) (ControllerCert, bool, error) {
	existing, err := loadControllerCert(ctx, db)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ControllerCert{}, false, err
	}

	cc, err := issueControllerCert(fleet)
	if err != nil {
		return ControllerCert{}, false, err
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO controller_cert (id, cert_pem, key_pem, serial, not_after)
		 VALUES (1, ?, ?, ?, ?)`,
		string(cc.CertPEM), string(cc.KeyPEM), cc.Serial, cc.Cert.NotAfter,
	); err != nil {
		return ControllerCert{}, false, fmt.Errorf("store controller cert: %w", err)
	}
	return cc, true, nil
}

// issueControllerCert mints a client certificate off the Fleet CA. coxswain dials
// nodes, so it is the TLS client: ClientAuth.
func issueControllerCert(fleet Authority) (ControllerCert, error) {
	if fleet.Role != RoleFleet {
		return ControllerCert{}, fmt.Errorf("issueControllerCert: expected fleet CA, got %q", fleet.Role)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ControllerCert{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return ControllerCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "coxswain-controller",
			Organization: []string{"PharosVPN"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, fleet.Cert, &key.PublicKey, fleet.Key)
	if err != nil {
		return ControllerCert{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ControllerCert{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ControllerCert{}, err
	}
	return ControllerCert{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Serial:  serial.String(),
	}, nil
}

func loadControllerCert(ctx context.Context, db *sql.DB) (ControllerCert, error) {
	var certPEM, keyPEM, serial string
	err := db.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem, serial FROM controller_cert WHERE id = 1`,
	).Scan(&certPEM, &keyPEM, &serial)
	if err != nil {
		return ControllerCert{}, err
	}
	cert, err := decodeCert([]byte(certPEM))
	if err != nil {
		return ControllerCert{}, fmt.Errorf("decode controller cert: %w", err)
	}
	return ControllerCert{
		Cert:    cert,
		CertPEM: []byte(certPEM),
		KeyPEM:  []byte(keyPEM),
		Serial:  serial,
	}, nil
}
