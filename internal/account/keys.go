// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SetEncryptionKey stores a user's X25519 public key and the passphrase-wrapped
// private key blob (DESIGN §8). coxswain holds the public key clear and the private
// key only as an opaque, passphrase-sealed blob.
func SetEncryptionKey(ctx context.Context, db *sql.DB, userID string, publicKey, wrappedPrivate []byte) error {
	res, err := db.ExecContext(ctx,
		`UPDATE users SET public_key = ?, wrapped_privkey = ?,
		        version = version + 1, updated_at = ?
		 WHERE id = ?`,
		publicKey, wrappedPrivate, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("set encryption key: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// GetEncryptionKey returns a user's X25519 public key and wrapped private key
// blob. Both are nil if the user has not yet enrolled an encryption key.
func GetEncryptionKey(ctx context.Context, db *sql.DB, userID string) (publicKey, wrappedPrivate []byte, err error) {
	err = db.QueryRowContext(ctx,
		`SELECT public_key, wrapped_privkey FROM users WHERE id = ?`, userID,
	).Scan(&publicKey, &wrappedPrivate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get encryption key: %w", err)
	}
	return publicKey, wrappedPrivate, nil
}
