// SPDX-License-Identifier: AGPL-3.0-or-later
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
