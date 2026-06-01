// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
)

// EnsureCA returns the CA bundle, generating and persisting it on first run.
// The boolean reports whether a new CA was created by this call.
func EnsureCA(ctx context.Context, db *sql.DB) (Bundle, bool, error) {
	existing, err := load(ctx, db)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, errNoCA) {
		return Bundle{}, false, err
	}

	bundle, err := GenerateBundle()
	if err != nil {
		return Bundle{}, false, err
	}
	if err := persist(ctx, db, bundle); err != nil {
		return Bundle{}, false, err
	}
	return bundle, true, nil
}

var errNoCA = errors.New("pki: no CA in database")

// persist writes all three authorities in a single transaction.
func persist(ctx context.Context, db *sql.DB, b Bundle) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	const q = `INSERT INTO ca (role, cert_pem, key_pem, serial, not_before, not_after)
	           VALUES (?, ?, ?, ?, ?, ?)`
	for _, a := range b.All() {
		if _, err := tx.ExecContext(ctx, q,
			a.Role, string(a.CertPEM), string(a.KeyPEM),
			a.Cert.SerialNumber.String(), a.Cert.NotBefore, a.Cert.NotAfter,
		); err != nil {
			return fmt.Errorf("insert %s CA: %w", a.Role, err)
		}
	}
	return tx.Commit()
}

// load reads the CA bundle back from the database. It returns errNoCA if the
// root row is absent.
func load(ctx context.Context, db *sql.DB) (Bundle, error) {
	root, err := loadAuthority(ctx, db, RoleRoot)
	if errors.Is(err, sql.ErrNoRows) {
		return Bundle{}, errNoCA
	}
	if err != nil {
		return Bundle{}, err
	}
	fleet, err := loadAuthority(ctx, db, RoleFleet)
	if err != nil {
		return Bundle{}, fmt.Errorf("load fleet CA: %w", err)
	}
	device, err := loadAuthority(ctx, db, RoleDevice)
	if err != nil {
		return Bundle{}, fmt.Errorf("load device CA: %w", err)
	}
	return Bundle{Root: root, Fleet: fleet, Device: device}, nil
}

func loadAuthority(ctx context.Context, db *sql.DB, role string) (Authority, error) {
	var certPEM, keyPEM string
	err := db.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem FROM ca WHERE role = ?`, role,
	).Scan(&certPEM, &keyPEM)
	if err != nil {
		return Authority{}, err
	}

	cert, err := decodeCert([]byte(certPEM))
	if err != nil {
		return Authority{}, fmt.Errorf("decode %s cert: %w", role, err)
	}
	key, err := decodeKey([]byte(keyPEM))
	if err != nil {
		return Authority{}, fmt.Errorf("decode %s key: %w", role, err)
	}
	return Authority{
		Role:    role,
		Cert:    cert,
		CertPEM: []byte(certPEM),
		Key:     key,
		KeyPEM:  []byte(keyPEM),
	}, nil
}

func decodeCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func decodeKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", key)
	}
	return ecKey, nil
}
