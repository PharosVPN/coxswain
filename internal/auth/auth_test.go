// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/db"
)

func newDB(t *testing.T) *sql.DB {
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

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !auth.VerifyPassword(hash, "correct horse battery staple") {
		t.Error("VerifyPassword rejected the correct password")
	}
	if auth.VerifyPassword(hash, "wrong password") {
		t.Error("VerifyPassword accepted a wrong password")
	}
	if auth.VerifyPassword("not-a-phc-string", "anything") {
		t.Error("VerifyPassword accepted a malformed hash")
	}

	// Two hashes of the same password differ (random salt).
	hash2, _ := auth.HashPassword("correct horse battery staple")
	if hash == hash2 {
		t.Error("two hashes of the same password are identical — salt not random")
	}
}

func TestSessionLifecycle(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Email: "s@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, err := auth.CreateSession(ctx, conn, user.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := auth.ResolveSession(ctx, conn, token)
	if err != nil || got != user.ID {
		t.Fatalf("ResolveSession: got %q %v", got, err)
	}

	if err := auth.DeleteSession(ctx, conn, token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := auth.ResolveSession(ctx, conn, token); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("ResolveSession after delete: got %v want ErrSessionInvalid", err)
	}
	if _, err := auth.ResolveSession(ctx, conn, "bogus-token"); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("ResolveSession unknown: got %v want ErrSessionInvalid", err)
	}
}

func TestSyncConfigAdmin(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	if err := auth.SyncConfigAdmin(ctx, conn, ""); err == nil {
		t.Error("SyncConfigAdmin accepted an empty password")
	}

	if err := auth.SyncConfigAdmin(ctx, conn, "first-password"); err != nil {
		t.Fatalf("SyncConfigAdmin: %v", err)
	}
	admin, err := account.GetUser(ctx, conn, account.FixedAdminID)
	if err != nil {
		t.Fatalf("GetUser(admin): %v", err)
	}
	if admin.Role != account.RoleAdmin || admin.Email != account.FixedAdminEmail {
		t.Errorf("admin record: %+v", admin)
	}
	if !auth.VerifyPassword(admin.PasswordHash, "first-password") {
		t.Error("synced admin password does not verify")
	}

	// Re-sync with a new password — config is the source of truth.
	if err := auth.SyncConfigAdmin(ctx, conn, "second-password"); err != nil {
		t.Fatalf("SyncConfigAdmin (re-sync): %v", err)
	}
	admin, _ = account.GetUser(ctx, conn, account.FixedAdminID)
	if !auth.VerifyPassword(admin.PasswordHash, "second-password") {
		t.Error("re-synced admin password does not verify")
	}
	if auth.VerifyPassword(admin.PasswordHash, "first-password") {
		t.Error("old admin password still verifies after re-sync")
	}
}
