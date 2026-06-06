// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package account_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
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

func TestUserCRUD(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := account.CreateUser(ctx, conn, account.User{
		Email: "ops@example.com", Role: account.RoleAdmin, PasswordHash: "hash",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == "" || created.Version != 1 || created.Status != account.StatusActive {
		t.Fatalf("CreateUser defaults: %+v", created)
	}

	byID, err := account.GetUser(ctx, conn, created.ID)
	if err != nil || byID.Email != "ops@example.com" {
		t.Fatalf("GetUser: %+v %v", byID, err)
	}
	byEmail, err := account.GetUserByEmail(ctx, conn, "ops@example.com")
	if err != nil || byEmail.ID != created.ID {
		t.Fatalf("GetUserByEmail: %+v %v", byEmail, err)
	}

	admins, err := account.ListUsersByRole(ctx, conn, account.RoleAdmin)
	if err != nil || len(admins) != 1 {
		t.Fatalf("ListUsersByRole: %d %v", len(admins), err)
	}

	if err := account.DeleteUser(ctx, conn, created.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := account.GetUser(ctx, conn, created.ID); !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("GetUser after delete: got %v want ErrNotFound", err)
	}
}

func TestUpdateUserOptimisticConcurrency(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	u, err := account.CreateUser(ctx, conn, account.User{Email: "a@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	stale := u

	u.Status = account.StatusDisabled
	if _, err := account.UpdateUser(ctx, conn, u); err != nil {
		t.Fatalf("UpdateUser (fresh): %v", err)
	}

	stale.Email = "b@example.com"
	if _, err := account.UpdateUser(ctx, conn, stale); !errors.Is(err, account.ErrStaleVersion) {
		t.Fatalf("UpdateUser (stale): got %v want ErrStaleVersion", err)
	}
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	if _, err := account.CreateUser(ctx, conn, account.User{Email: "dup@example.com"}); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	if _, err := account.CreateUser(ctx, conn, account.User{Email: "dup@example.com"}); !errors.Is(err, account.ErrEmailTaken) {
		t.Fatalf("duplicate CreateUser: got %v want ErrEmailTaken", err)
	}
}

// TestUsersOptionalContact guards the identity model: a user needs only a name —
// email and phone are optional (stored NULL, so many users may have neither),
// and each resolves a user when present.
func TestUsersOptionalContact(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	// Two users with no email or phone — allowed (NULLs are distinct).
	a, err := account.CreateUser(ctx, conn, account.User{Name: "Ann"})
	if err != nil {
		t.Fatalf("create Ann: %v", err)
	}
	if _, err := account.CreateUser(ctx, conn, account.User{Name: "Bob"}); err != nil {
		t.Fatalf("create Bob (2nd email-less): %v", err)
	}

	// A user with a phone but no email resolves by phone, not email.
	c, err := account.CreateUser(ctx, conn, account.User{Name: "Cara", Phone: "+15551234567"})
	if err != nil {
		t.Fatalf("create Cara: %v", err)
	}
	got, err := account.GetUserByPhone(ctx, conn, "+15551234567")
	if err != nil || got.ID != c.ID || got.Name != "Cara" {
		t.Fatalf("GetUserByPhone: got %+v err %v", got, err)
	}
	if _, err := account.GetUserByEmail(ctx, conn, ""); !errors.Is(err, account.ErrNotFound) {
		t.Errorf("GetUserByEmail(\"\"): got %v want ErrNotFound", err)
	}
	if got, err := account.GetUser(ctx, conn, a.ID); err != nil || got.Email != "" || got.Phone != "" {
		t.Errorf("Ann round-trip: %+v err %v (want blank email/phone)", got, err)
	}

	// Phone is unique too.
	if _, err := account.CreateUser(ctx, conn, account.User{Name: "Dup", Phone: "+15551234567"}); !errors.Is(err, account.ErrEmailTaken) {
		t.Errorf("duplicate phone: got %v want ErrEmailTaken", err)
	}
}
