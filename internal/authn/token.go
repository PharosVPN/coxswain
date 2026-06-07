// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package authn issues and authenticates coxswain's scoped API tokens — the
// bearer credentials that grant programmatic access to the admin API alongside
// the session cookie. A token carries one scope ('readonly' < 'monitor' <
// 'admin') that gates what its bearer may do.
//
// The plaintext secret has the form
//
//	cox_<scopeabbr>_<base64url(32 random crypto/rand bytes)>
//
// where scopeabbr is ro/mon/adm. coxswain persists only the hex SHA-256 of the
// secret plus a short non-secret prefix for display; the plaintext is returned
// exactly once from Create and never stored.
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// Scope is an API token's privilege level. Scopes are totally ordered:
// readonly < monitor < admin.
type Scope string

// The three token scopes, in increasing privilege.
const (
	ScopeReadonly Scope = "readonly"
	ScopeMonitor  Scope = "monitor"
	ScopeAdmin    Scope = "admin"
)

// rank returns a scope's privilege rank (higher = more privileged), or -1 for
// an unknown scope.
func (s Scope) rank() int {
	switch s {
	case ScopeReadonly:
		return 0
	case ScopeMonitor:
		return 1
	case ScopeAdmin:
		return 2
	default:
		return -1
	}
}

// Valid reports whether s is one of the three known scopes.
func (s Scope) Valid() bool { return s.rank() >= 0 }

// abbr is the short scope tag embedded in the token secret (ro/mon/adm).
func (s Scope) abbr() string {
	switch s {
	case ScopeReadonly:
		return "ro"
	case ScopeMonitor:
		return "mon"
	case ScopeAdmin:
		return "adm"
	default:
		return "ro"
	}
}

// ParseScope validates and returns a scope, or an error for an unknown value.
func ParseScope(s string) (Scope, error) {
	sc := Scope(s)
	if !sc.Valid() {
		return "", fmt.Errorf("authn: unknown scope %q (want readonly|monitor|admin)", s)
	}
	return sc, nil
}

// Token-authentication errors.
var (
	// ErrInvalidToken is returned when no token matches the presented secret.
	ErrInvalidToken = errors.New("authn: token not recognised")
	// ErrTokenExpired is returned for a token past its expiry.
	ErrTokenExpired = errors.New("authn: token expired")
	// ErrTokenRevoked is returned for a token that was revoked.
	ErrTokenRevoked = errors.New("authn: token revoked")
	// ErrNotFound is returned when a token id does not exist.
	ErrNotFound = errors.New("authn: token not found")
)

// secretPrefixLen is how many leading characters of the plaintext secret are
// stored (un-hashed) for display in listings. It covers "cox_<abbr>_" plus a
// couple of body characters — never enough to reconstruct the secret.
const secretPrefixLen = 12

// Token is one API token record (the `api_tokens` table). It never carries the
// plaintext secret — only the stored hash/prefix and metadata.
type Token struct {
	ID         string
	Name       string
	Scope      Scope
	TokenHash  string
	Prefix     string
	CreatedAt  time.Time
	CreatedBy  string
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Revoked reports whether the token has been revoked.
func (t Token) Revoked() bool { return t.RevokedAt != nil }

// Expired reports whether the token has an expiry that is in the past at now.
func (t Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && now.After(*t.ExpiresAt)
}

// Allows reports whether the token's scope is at least the required scope
// (using the readonly < monitor < admin ranking). An unknown required scope is
// never allowed.
func (t Token) Allows(required Scope) bool {
	rr := required.rank()
	if rr < 0 {
		return false
	}
	return t.Scope.rank() >= rr
}

// Create mints a new API token with the given name and scope. ttl is the token
// lifetime; ttl <= 0 means the token never expires. It returns the plaintext
// secret (shown to the operator exactly once and never persisted) and the
// stored record. createdBy records who minted it (a username or "cli").
func Create(ctx context.Context, db *sql.DB, name string, scope Scope, ttl time.Duration, createdBy string) (secret string, rec Token, err error) {
	if !scope.Valid() {
		return "", Token{}, fmt.Errorf("authn: create token: unknown scope %q", scope)
	}
	if strings.TrimSpace(name) == "" {
		return "", Token{}, errors.New("authn: create token: name is required")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Token{}, fmt.Errorf("authn: create token: %w", err)
	}
	secret = "cox_" + scope.abbr() + "_" + base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	rec = Token{
		ID:        idgen.New("tok"),
		Name:      name,
		Scope:     scope,
		TokenHash: hashSecret(secret),
		Prefix:    secretPrefix(secret),
		CreatedAt: now,
		CreatedBy: createdBy,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		rec.ExpiresAt = &exp
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, name, scope, token_hash, token_prefix, created_at, created_by, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Name, string(rec.Scope), rec.TokenHash, rec.Prefix, rec.CreatedAt, rec.CreatedBy, rec.ExpiresAt)
	if err != nil {
		return "", Token{}, fmt.Errorf("authn: create token: %w", err)
	}
	return secret, rec, nil
}

const tokenColumns = `id, name, scope, token_hash, token_prefix, created_at, created_by, expires_at, last_used_at, revoked_at`

// List returns every API token, newest first. Secrets are never returned.
func List(ctx context.Context, db *sql.DB) ([]Token, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("authn: list tokens: %w", err)
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns the token with the given id, or ErrNotFound.
func Get(ctx context.Context, db *sql.DB, id string) (Token, error) {
	row := db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens WHERE id = ?`, id)
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return t, err
}

// Revoke marks the token with the given id revoked (idempotent — re-revoking
// keeps the original timestamp). A missing id yields ErrNotFound.
func Revoke(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("authn: revoke token: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		// Either the token is gone, or it was already revoked (a no-op).
		if _, gErr := Get(ctx, db, id); errors.Is(gErr, ErrNotFound) {
			return ErrNotFound
		}
	}
	return nil
}

// Authenticate resolves a presented plaintext secret to its token, rejecting an
// unknown, expired, or revoked token. On success it best-effort stamps
// last_used_at (a failure there does not fail authentication). The hash compare
// is constant-time. An empty secret is rejected as ErrInvalidToken.
func Authenticate(ctx context.Context, db *sql.DB, secret string) (Token, error) {
	if secret == "" {
		return Token{}, ErrInvalidToken
	}
	want := hashSecret(secret)
	row := db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens WHERE token_hash = ?`, want)
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrInvalidToken
	}
	if err != nil {
		return Token{}, err
	}
	// Defence in depth: the lookup already matched on the hash, but compare in
	// constant time so the path is uniform regardless of how the row was found.
	if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(want)) != 1 {
		return Token{}, ErrInvalidToken
	}
	if t.Revoked() {
		return Token{}, ErrTokenRevoked
	}
	if t.Expired(time.Now().UTC()) {
		return Token{}, ErrTokenExpired
	}

	// Best-effort last-used stamp — never fail auth on a write error.
	now := time.Now().UTC()
	if _, uErr := db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now, t.ID); uErr == nil {
		t.LastUsedAt = &now
	}
	return t, nil
}

// hashSecret returns the hex SHA-256 of a token secret — the value stored and
// compared. The plaintext is never persisted.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// secretPrefix returns the leading, non-secret display prefix of a secret.
func secretPrefix(secret string) string {
	if len(secret) <= secretPrefixLen {
		return secret
	}
	return secret[:secretPrefixLen]
}

func scanToken(s interface{ Scan(dest ...any) error }) (Token, error) {
	var (
		t        Token
		scope    string
		expires  sql.NullTime
		lastUsed sql.NullTime
		revoked  sql.NullTime
	)
	err := s.Scan(&t.ID, &t.Name, &scope, &t.TokenHash, &t.Prefix,
		&t.CreatedAt, &t.CreatedBy, &expires, &lastUsed, &revoked)
	if err != nil {
		return Token{}, err
	}
	t.Scope = Scope(scope)
	if expires.Valid {
		e := expires.Time.UTC()
		t.ExpiresAt = &e
	}
	if lastUsed.Valid {
		l := lastUsed.Time.UTC()
		t.LastUsedAt = &l
	}
	if revoked.Valid {
		r := revoked.Time.UTC()
		t.RevokedAt = &r
	}
	return t, nil
}
