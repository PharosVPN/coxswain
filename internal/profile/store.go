// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/idgen"
)

var (
	// ErrNoEncryptionKey is returned when issuing to a user who has not
	// enrolled an X25519 key — there is no recipient to seal to.
	ErrNoEncryptionKey = errors.New("profile: user has not enrolled an encryption key")
	// ErrNoProfile is returned when a user has no issued profile.
	ErrNoProfile = errors.New("profile: no profile issued for user")
)

// Issue seals profile p to the user end-to-end and stores the ciphertext as a
// new revision for the given device. coxswain keeps only ciphertext — the
// plaintext is discarded once sealed. Each device has its own revision sequence
// (so a device's profile is independent of the user's other devices). A blank
// deviceID stores a legacy per-user profile (device_id NULL). Returns the new
// revision number.
func Issue(ctx context.Context, db *sql.DB, userID, deviceID string, p Profile) (int64, error) {
	recipient, _, err := account.GetEncryptionKey(ctx, db, userID)
	if err != nil {
		return 0, err
	}
	if len(recipient) == 0 {
		return 0, ErrNoEncryptionKey
	}
	signing, _, err := EnsureSigningKey(ctx, db)
	if err != nil {
		return 0, err
	}

	var prev int64
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0) FROM profiles WHERE user_id = ? AND `+deviceFilter(deviceID),
		deviceArgs(userID, deviceID)...,
	).Scan(&prev); err != nil {
		return 0, fmt.Errorf("profile: read revision: %w", err)
	}

	p.User = userID
	p.Revision = prev + 1
	if p.IssuedAt.IsZero() {
		p.IssuedAt = time.Now().UTC()
	}

	plaintext, err := json.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("profile: marshal: %w", err)
	}
	bundle, err := e2e.Seal(plaintext, recipient, signing.Private)
	if err != nil {
		return 0, err
	}
	ciphertext, err := json.Marshal(bundle)
	if err != nil {
		return 0, fmt.Errorf("profile: marshal bundle: %w", err)
	}

	var dev any
	if deviceID != "" {
		dev = deviceID
	}
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO profiles (id, user_id, device_id, revision, ciphertext, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		idgen.New("prof"), userID, dev, p.Revision, ciphertext, now, now,
	); err != nil {
		return 0, fmt.Errorf("profile: store: %w", err)
	}
	return p.Revision, nil
}

// LatestCiphertext returns the most recent sealed profile bundle for a user's
// device, as the JSON-encoded e2e.SealedBundle coxswain stores. A blank deviceID
// reads the legacy per-user profile (device_id NULL).
func LatestCiphertext(ctx context.Context, db *sql.DB, userID, deviceID string) (ciphertext []byte, revision int64, err error) {
	err = db.QueryRowContext(ctx,
		`SELECT ciphertext, revision FROM profiles
		 WHERE user_id = ? AND `+deviceFilter(deviceID)+` ORDER BY revision DESC LIMIT 1`,
		deviceArgs(userID, deviceID)...,
	).Scan(&ciphertext, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNoProfile
	}
	if err != nil {
		return nil, 0, fmt.Errorf("profile: read: %w", err)
	}
	return ciphertext, revision, nil
}

// deviceFilter / deviceArgs build the device-scoped WHERE clause: `device_id = ?`
// for a real device, `device_id IS NULL` for the legacy per-user row.
func deviceFilter(deviceID string) string {
	if deviceID == "" {
		return "device_id IS NULL"
	}
	return "device_id = ?"
}

func deviceArgs(userID, deviceID string) []any {
	if deviceID == "" {
		return []any{userID}
	}
	return []any{userID, deviceID}
}
