// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// SessionTTL is how long a login session stays valid.
const SessionTTL = 12 * time.Hour

// ErrSessionInvalid is returned for an unknown or expired session token.
var ErrSessionInvalid = errors.New("auth: session invalid or expired")

// CreateSession issues a new session for userID and returns the opaque token.
// Only the token's SHA-256 is stored — never the token itself.
func CreateSession(ctx context.Context, db *sql.DB, userID string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("auth: session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		idgen.New("ses"), userID, hashToken(token), now.Add(SessionTTL), now,
	); err != nil {
		return "", fmt.Errorf("auth: create session: %w", err)
	}
	return token, nil
}

// ResolveSession returns the user ID a token belongs to, or ErrSessionInvalid.
func ResolveSession(ctx context.Context, db *sql.DB, token string) (string, error) {
	var (
		userID    string
		expiresAt time.Time
	)
	err := db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, hashToken(token),
	).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrSessionInvalid
	}
	if err != nil {
		return "", err
	}
	if time.Now().UTC().After(expiresAt) {
		return "", ErrSessionInvalid
	}
	return userID, nil
}

// DeleteSession revokes a session token (logout).
func DeleteSession(ctx context.Context, db *sql.DB, token string) error {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token)); err != nil {
		return fmt.Errorf("auth: delete session: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
