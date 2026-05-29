// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/PharosVPN/coxswain/internal/account"
)

// SyncConfigAdmin reconciles the fixed controller-admin account with the
// password from the config file. The config is the source of truth, so this
// runs on every start: the admin is created if absent, and its password is
// re-hashed and stored each time (DESIGN §8, the M5 admin model).
func SyncConfigAdmin(ctx context.Context, db *sql.DB, password string) error {
	if password == "" {
		return errors.New("auth: admin.password is not set in the config")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	existing, err := account.GetUser(ctx, db, account.FixedAdminID)
	switch {
	case errors.Is(err, account.ErrNotFound):
		_, err = account.CreateUser(ctx, db, account.User{
			ID:           account.FixedAdminID,
			Email:        account.FixedAdminEmail,
			Role:         account.RoleAdmin,
			Status:       account.StatusActive,
			PasswordHash: hash,
		})
		return err
	case err != nil:
		return err
	default:
		existing.Email = account.FixedAdminEmail
		existing.Role = account.RoleAdmin
		existing.Status = account.StatusActive
		existing.PasswordHash = hash
		_, err = account.UpdateUser(ctx, db, existing)
		return err
	}
}
