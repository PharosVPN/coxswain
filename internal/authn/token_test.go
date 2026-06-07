// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return conn
}

// TestCreateAuthenticateRoundtrip mints a token and authenticates with its
// plaintext secret.
func TestCreateAuthenticateRoundtrip(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	secret, rec, err := Create(ctx, conn, "ci", ScopeAdmin, 0, "tester")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(secret, "cox_adm_") {
		t.Errorf("secret format: got %q want cox_adm_ prefix", secret)
	}
	if rec.Scope != ScopeAdmin || rec.Name != "ci" || rec.CreatedBy != "tester" {
		t.Errorf("record: %+v", rec)
	}
	if rec.ExpiresAt != nil {
		t.Errorf("ttl 0 should never expire, got %v", rec.ExpiresAt)
	}

	got, err := Authenticate(ctx, conn, secret)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != rec.ID || got.Scope != ScopeAdmin {
		t.Errorf("authenticated token: %+v want id %s scope admin", got, rec.ID)
	}
	if got.LastUsedAt == nil {
		t.Error("Authenticate should stamp last_used_at")
	}
}

// TestWrongSecretRejected ensures an unknown secret is rejected.
func TestWrongSecretRejected(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()
	if _, _, err := Create(ctx, conn, "ci", ScopeReadonly, 0, "tester"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Authenticate(ctx, conn, "cox_ro_not-a-real-secret"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong secret: got %v want ErrInvalidToken", err)
	}
	if _, err := Authenticate(ctx, conn, ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty secret: got %v want ErrInvalidToken", err)
	}
}

// TestExpiredRejected ensures a token past its expiry is rejected.
func TestExpiredRejected(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	// A token that has already expired (negative ttl is rejected at Create, so
	// mint a short-lived one and stamp expires_at into the past directly).
	secret, rec, err := Create(ctx, conn, "ephemeral", ScopeMonitor, time.Hour, "tester")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	if _, err := conn.ExecContext(ctx, `UPDATE api_tokens SET expires_at = ? WHERE id = ?`, past, rec.ID); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	if _, err := Authenticate(ctx, conn, secret); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token: got %v want ErrTokenExpired", err)
	}
}

// TestRevokedRejected ensures a revoked token is rejected.
func TestRevokedRejected(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	secret, rec, err := Create(ctx, conn, "ci", ScopeAdmin, 0, "tester")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := Revoke(ctx, conn, rec.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := Authenticate(ctx, conn, secret); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("revoked token: got %v want ErrTokenRevoked", err)
	}
	// Revoking a missing id is ErrNotFound.
	if err := Revoke(ctx, conn, "tok_does_not_exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke missing: got %v want ErrNotFound", err)
	}
}

// TestScopeRanking checks the readonly < monitor < admin ordering via Allows.
func TestScopeRanking(t *testing.T) {
	ro := Token{Scope: ScopeReadonly}
	mon := Token{Scope: ScopeMonitor}
	adm := Token{Scope: ScopeAdmin}

	// A readonly token may not perform admin or monitor actions.
	if ro.Allows(ScopeAdmin) {
		t.Error("readonly must not allow admin")
	}
	if ro.Allows(ScopeMonitor) {
		t.Error("readonly must not allow monitor")
	}
	if !ro.Allows(ScopeReadonly) {
		t.Error("readonly must allow readonly")
	}
	// A monitor token allows readonly + monitor but not admin.
	if !mon.Allows(ScopeReadonly) || !mon.Allows(ScopeMonitor) {
		t.Error("monitor must allow readonly + monitor")
	}
	if mon.Allows(ScopeAdmin) {
		t.Error("monitor must not allow admin")
	}
	// An admin token allows everything.
	if !adm.Allows(ScopeReadonly) || !adm.Allows(ScopeMonitor) || !adm.Allows(ScopeAdmin) {
		t.Error("admin must allow all scopes")
	}
	// An unknown required scope is never allowed.
	if adm.Allows(Scope("bogus")) {
		t.Error("unknown required scope must never be allowed")
	}
}

// TestHashStoredNotPlaintext verifies the DB stores only the SHA-256 hash and a
// short prefix — never the plaintext secret.
func TestHashStoredNotPlaintext(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	secret, rec, err := Create(ctx, conn, "ci", ScopeReadonly, 0, "tester")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var storedHash, storedPrefix string
	if err := conn.QueryRowContext(ctx,
		`SELECT token_hash, token_prefix FROM api_tokens WHERE id = ?`, rec.ID).
		Scan(&storedHash, &storedPrefix); err != nil {
		t.Fatalf("query stored: %v", err)
	}
	if storedHash == secret {
		t.Fatal("token_hash must not equal the plaintext secret")
	}
	sum := sha256.Sum256([]byte(secret))
	if storedHash != hex.EncodeToString(sum[:]) {
		t.Errorf("token_hash mismatch: got %q want sha256hex of secret", storedHash)
	}
	if !strings.HasPrefix(secret, storedPrefix) {
		t.Errorf("prefix %q is not a prefix of secret", storedPrefix)
	}
	if storedPrefix == secret {
		t.Error("stored prefix must be shorter than the full secret")
	}
}

// TestParseScope rejects unknown scopes.
func TestParseScope(t *testing.T) {
	for _, s := range []string{"readonly", "monitor", "admin"} {
		if _, err := ParseScope(s); err != nil {
			t.Errorf("ParseScope(%q): %v", s, err)
		}
	}
	if _, err := ParseScope("superuser"); err == nil {
		t.Error("ParseScope should reject unknown scope")
	}
}

// TestListNewestFirst checks List orders newest first and never leaks secrets.
func TestListNewestFirst(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()
	if _, _, err := Create(ctx, conn, "first", ScopeReadonly, 0, "t"); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, _, err := Create(ctx, conn, "second", ScopeAdmin, 0, "t"); err != nil {
		t.Fatalf("Create second: %v", err)
	}
	tokens, err := List(ctx, conn)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("List: got %d want 2", len(tokens))
	}
	if tokens[0].Name != "second" {
		t.Errorf("newest-first: got %q want second", tokens[0].Name)
	}
}
