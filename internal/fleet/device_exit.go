// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DeviceExit is a device's chosen cascade exit — the node_link (entry→exit
// edge) its traffic egresses through (the `device_exits` table, DESIGN §3
// decision 18). At most one per device.
type DeviceExit struct {
	DeviceID   string
	NodeLinkID string
	Version    int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// GetDeviceExit returns a device's cascade binding, or ErrNotFound if the
// device egresses normally (no cascade).
func GetDeviceExit(ctx context.Context, db *sql.DB, deviceID string) (DeviceExit, error) {
	var de DeviceExit
	err := db.QueryRowContext(ctx,
		`SELECT device_id, node_link_id, version, created_at, updated_at
		 FROM device_exits WHERE device_id = ?`, deviceID).
		Scan(&de.DeviceID, &de.NodeLinkID, &de.Version, &de.CreatedAt, &de.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceExit{}, ErrNotFound
	}
	if err != nil {
		return DeviceExit{}, fmt.Errorf("get device exit: %w", err)
	}
	return de, nil
}

// SetDeviceExit binds a device to a cascade exit, replacing any existing
// binding (the live exit-switch). It is an upsert keyed by device_id.
func SetDeviceExit(ctx context.Context, db *sql.DB, deviceID, nodeLinkID string) error {
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx,
		`INSERT INTO device_exits (device_id, node_link_id, version, created_at, updated_at)
		 VALUES (?, ?, 1, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET
		     node_link_id = excluded.node_link_id,
		     version = device_exits.version + 1,
		     updated_at = excluded.updated_at`,
		deviceID, nodeLinkID, now, now)
	if err != nil {
		return fmt.Errorf("set device exit: %w", err)
	}
	return nil
}

// DeleteDeviceExit removes a device's cascade binding (back to normal egress).
// Removing a missing binding is not an error.
func DeleteDeviceExit(ctx context.Context, db *sql.DB, deviceID string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM device_exits WHERE device_id = ?`, deviceID); err != nil {
		return fmt.Errorf("delete device exit: %w", err)
	}
	return nil
}

// ListDeviceIDsByLink returns the devices bound to a node_link, oldest first.
func ListDeviceIDsByLink(ctx context.Context, db *sql.DB, nodeLinkID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT device_id FROM device_exits WHERE node_link_id = ? ORDER BY created_at`, nodeLinkID)
	if err != nil {
		return nil, fmt.Errorf("list device exits by link: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
