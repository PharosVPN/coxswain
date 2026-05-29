// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package account is coxswain's domain layer over user accounts — the
// authentication principals of DESIGN §8. M5 uses it for admin accounts;
// M6 extends it with end-user accounts and E2E profile keys.
package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

var (
	// ErrNotFound is returned when a user does not exist.
	ErrNotFound = errors.New("account: user not found")
	// ErrStaleVersion is returned on an optimistic-concurrency conflict.
	ErrStaleVersion = errors.New("account: user changed by another writer")
	// ErrEmailTaken is returned when an email is already registered.
	ErrEmailTaken = errors.New("account: email already in use")
)

// Account roles.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Account statuses.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// FixedAdminID and FixedAdminEmail identify the built-in controller admin —
// config-driven and undeletable (the M5 admin model, DESIGN §8).
const (
	FixedAdminID    = "usr_admin"
	FixedAdminEmail = "admin"
)

// User is an account record (the `users` table).
type User struct {
	ID           string
	Email        string
	Role         string
	Status       string
	PasswordHash string
	Version      int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type rowScanner interface {
	Scan(dest ...any) error
}

const userColumns = `id, email, role, status, password_hash, version, created_at, updated_at`

// CreateUser inserts a new user. ID, Status, and Version are defaulted if
// unset. A duplicate email yields ErrEmailTaken.
func CreateUser(ctx context.Context, db *sql.DB, u User) (User, error) {
	if u.ID == "" {
		u.ID = idgen.New("usr")
	}
	if u.Role == "" {
		u.Role = RoleUser
	}
	if u.Status == "" {
		u.Status = StatusActive
	}
	now := time.Now().UTC()
	u.Version = 1
	u.CreatedAt, u.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Role, u.Status, u.PasswordHash, u.Version, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUser returns the user with the given ID, or ErrNotFound.
func GetUser(ctx context.Context, db *sql.DB, id string) (User, error) {
	row := db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUserResult(row)
}

// GetUserByEmail returns the user with the given email, or ErrNotFound.
func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (User, error) {
	row := db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, email)
	return scanUserResult(row)
}

// ListUsersByRole returns every user with the given role, oldest first.
func ListUsersByRole(ctx context.Context, db *sql.DB, role string) ([]User, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE role = ? ORDER BY created_at`, role)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser writes u back under optimistic concurrency: it succeeds only if
// u.Version matches the stored row. A stale version yields ErrStaleVersion;
// a missing row yields ErrNotFound.
func UpdateUser(ctx context.Context, db *sql.DB, u User) (User, error) {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE users SET email = ?, role = ?, status = ?, password_hash = ?,
		        version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		u.Email, u.Role, u.Status, u.PasswordHash, now, u.ID, u.Version)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("update user: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if affected == 0 {
		if _, gErr := GetUser(ctx, db, u.ID); errors.Is(gErr, ErrNotFound) {
			return User{}, ErrNotFound
		}
		return User{}, ErrStaleVersion
	}
	u.Version++
	u.UpdatedAt = now
	return u, nil
}

// DeleteUser removes a user. A missing row yields ErrNotFound.
func DeleteUser(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
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

func scanUserResult(row *sql.Row) (User, error) {
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func scanUser(s rowScanner) (User, error) {
	var u User
	err := s.Scan(&u.ID, &u.Email, &u.Role, &u.Status, &u.PasswordHash,
		&u.Version, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
