// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

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

// TokenTTL is the lifetime of a bootstrap token (DESIGN §4: 24 hours).
const TokenTTL = 24 * time.Hour

// Bootstrap token kinds — which role enrols with the token.
const (
	KindBuoy   = "buoy"
	KindBeacon = "beacon"
)

// Bootstrap token errors.
var (
	ErrTokenInvalid = errors.New("fleet: bootstrap token not recognised")
	ErrTokenExpired = errors.New("fleet: bootstrap token expired")
	ErrTokenUsed    = errors.New("fleet: bootstrap token already used")
)

// Token is a one-time enrollment token (the `bootstrap_tokens` table). coxswain
// stores only the SHA-256 of the secret — never the secret itself.
type Token struct {
	ID        string
	Kind      string
	NodeID    string // empty if not yet bound to a node
	ExpiresAt time.Time
	UsedAt    *time.Time // nil while unredeemed
	CreatedAt time.Time
}

// Used reports whether the token has been redeemed.
func (t Token) Used() bool { return t.UsedAt != nil }

// IssueToken mints a bootstrap token of the given kind, optionally bound to a
// node. It returns the stored record and the plaintext secret, which is shown
// to the operator exactly once and never persisted.
func IssueToken(ctx context.Context, db *sql.DB, kind, nodeID string) (Token, string, error) {
	switch kind {
	case KindBuoy, KindBeacon:
	default:
		return Token{}, "", fmt.Errorf("issue token: unknown kind %q", kind)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, "", fmt.Errorf("issue token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	t := Token{
		ID:        idgen.New("tok"),
		Kind:      kind,
		NodeID:    nodeID,
		ExpiresAt: now.Add(TokenTTL),
		CreatedAt: now,
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO bootstrap_tokens (id, token_hash, kind, node_id, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, hashToken(secret), t.Kind, nullString(nodeID), t.ExpiresAt, t.CreatedAt)
	if err != nil {
		return Token{}, "", fmt.Errorf("issue token: %w", err)
	}
	return t, secret, nil
}

// RedeemToken validates a plaintext token and marks it used in one atomic step.
// It returns ErrTokenInvalid, ErrTokenExpired, or ErrTokenUsed as appropriate.
func RedeemToken(ctx context.Context, db *sql.DB, secret string) (Token, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	var (
		t      Token
		nodeID sql.NullString
		usedAt sql.NullTime
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, kind, node_id, expires_at, used_at, created_at
		 FROM bootstrap_tokens WHERE token_hash = ?`, hashToken(secret),
	).Scan(&t.ID, &t.Kind, &nodeID, &t.ExpiresAt, &usedAt, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrTokenInvalid
	}
	if err != nil {
		return Token{}, err
	}
	t.NodeID = nodeID.String

	if usedAt.Valid {
		return Token{}, ErrTokenUsed
	}
	if time.Now().UTC().After(t.ExpiresAt) {
		return Token{}, ErrTokenExpired
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE bootstrap_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		now, t.ID)
	if err != nil {
		return Token{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return Token{}, ErrTokenUsed // lost a race with a concurrent redeem
	}
	if err := tx.Commit(); err != nil {
		return Token{}, err
	}
	t.UsedAt = &now
	return t, nil
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
