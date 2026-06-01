// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"

	"github.com/PharosVPN/coxswain/internal/e2e"
)

// SigningKey is coxswain's Ed25519 profile-signing keypair. coxswain signs every
// sealed profile bundle with it; devices pin the public key to verify origin.
type SigningKey struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// EnsureSigningKey returns coxswain's profile-signing key, generating one on first
// call. The boolean reports whether a key was created.
func EnsureSigningKey(ctx context.Context, db *sql.DB) (SigningKey, bool, error) {
	var pub, priv []byte
	err := db.QueryRowContext(ctx,
		`SELECT public_key, private_key FROM profile_signing_key WHERE id = 1`,
	).Scan(&pub, &priv)
	if err == nil {
		return SigningKey{Public: pub, Private: priv}, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SigningKey{}, false, err
	}

	newPub, newPriv, err := e2e.GenerateSigningKey()
	if err != nil {
		return SigningKey{}, false, err
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO profile_signing_key (id, public_key, private_key) VALUES (1, ?, ?)`,
		[]byte(newPub), []byte(newPriv),
	); err != nil {
		return SigningKey{}, false, fmt.Errorf("store profile signing key: %w", err)
	}
	return SigningKey{Public: newPub, Private: newPriv}, true, nil
}
