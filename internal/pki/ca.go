// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package pki generates and stores coxswain's in-repo certificate authority: the
// self-signed root and the Fleet/Device intermediates (DESIGN §4).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CA roles, matching the `ca` table's primary key.
const (
	RoleRoot   = "root"
	RoleFleet  = "fleet"
	RoleDevice = "device"
)

const (
	rootValidity         = 10 * 365 * 24 * time.Hour
	intermediateValidity = 5 * 365 * 24 * time.Hour
)

// Authority is one certificate authority — the cert plus its private key, in
// both parsed and PEM-encoded form.
type Authority struct {
	Role    string
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey
	KeyPEM  []byte
}

// Fingerprint returns the lowercase hex SHA-256 of the DER certificate. It is
// the value clients pin in enrollment tickets (DESIGN §9).
func (a Authority) Fingerprint() string {
	sum := sha256.Sum256(a.Cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Bundle is the complete three-tier CA.
type Bundle struct {
	Root   Authority
	Fleet  Authority
	Device Authority
}

// All returns the authorities in dependency order (root first).
func (b Bundle) All() []Authority {
	return []Authority{b.Root, b.Fleet, b.Device}
}

// GenerateBundle mints a fresh root CA and its two intermediates. It is called
// once, on coxswain's first run.
func GenerateBundle() (Bundle, error) {
	root, err := generateRoot()
	if err != nil {
		return Bundle{}, fmt.Errorf("generate root CA: %w", err)
	}
	fleet, err := generateIntermediate(root, RoleFleet, "PharosVPN Fleet CA")
	if err != nil {
		return Bundle{}, fmt.Errorf("generate fleet CA: %w", err)
	}
	device, err := generateIntermediate(root, RoleDevice, "PharosVPN Device CA")
	if err != nil {
		return Bundle{}, fmt.Errorf("generate device CA: %w", err)
	}
	return Bundle{Root: root, Fleet: fleet, Device: device}, nil
}

func generateRoot() (Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Authority{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "PharosVPN Root CA",
			Organization: []string{"PharosVPN"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // root → intermediate → leaf
	}
	return finalize(RoleRoot, tmpl, tmpl, &key.PublicKey, key, key)
}

func generateIntermediate(parent Authority, role, cn string) (Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Authority{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"PharosVPN"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(intermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // signs leaves only
		MaxPathLenZero:        true,
	}
	return finalize(role, tmpl, parent.Cert, &key.PublicKey, key, parent.Key)
}

// finalize signs tmpl with signerKey, parses the result, and PEM-encodes both
// the certificate and ownerKey.
func finalize(role string, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, ownerKey, signerKey *ecdsa.PrivateKey) (Authority, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
	if err != nil {
		return Authority{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Authority{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ownerKey)
	if err != nil {
		return Authority{}, err
	}
	return Authority{
		Role:    role,
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:     ownerKey,
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// newSerial returns a random 128-bit positive certificate serial number.
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
