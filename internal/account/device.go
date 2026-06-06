// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package account

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// Device is a user's enrolled endpoint — a caravel install or admin browser
// (the `devices` table).
type Device struct {
	ID          string
	UserID      string
	Name        string
	Platform    string
	Fingerprint string
	Status      string
	Version     int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const deviceColumns = `id, user_id, name, platform, fingerprint, status,
	version, created_at, updated_at`

// CreateDevice inserts a new device. ID and Status are defaulted if unset.
func CreateDevice(ctx context.Context, db *sql.DB, d Device) (Device, error) {
	if d.ID == "" {
		d.ID = idgen.New("dev")
	}
	if d.Status == "" {
		d.Status = StatusActive
	}
	now := time.Now().UTC()
	d.Version = 1
	d.CreatedAt, d.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO devices (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.Name, d.Platform, d.Fingerprint, d.Status,
		d.Version, d.CreatedAt, d.UpdatedAt)
	if err != nil {
		return Device{}, fmt.Errorf("create device: %w", err)
	}
	return d, nil
}

// GetDevice returns the device with the given ID, or ErrNotFound.
func GetDevice(ctx context.Context, db *sql.DB, id string) (Device, error) {
	var d Device
	err := db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id,
	).Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.Fingerprint, &d.Status,
		&d.Version, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("get device: %w", err)
	}
	return d, nil
}

// GetDeviceByFingerprint returns the device whose Device-CA leaf has the given
// fingerprint (the trusted `x-pharos-device-fp` the relay forwards after mTLS),
// or ErrNotFound. This is how account sync identifies the *device* behind a call.
func GetDeviceByFingerprint(ctx context.Context, db *sql.DB, fingerprint string) (Device, error) {
	if fingerprint == "" {
		return Device{}, ErrNotFound
	}
	var d Device
	err := db.QueryRowContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE fingerprint = ?`, fingerprint,
	).Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.Fingerprint, &d.Status,
		&d.Version, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("get device by fingerprint: %w", err)
	}
	return d, nil
}

// ListDevicesByUser returns a user's devices, oldest first.
func ListDevicesByUser(ctx context.Context, db *sql.DB, userID string) ([]Device, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT `+deviceColumns+` FROM devices WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.Fingerprint,
			&d.Status, &d.Version, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDevice removes a device. A missing row yields ErrNotFound.
func DeleteDevice(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete device: %w", err)
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
