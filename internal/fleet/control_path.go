// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// ControlPath is one entry in the `control_paths` table: a named, ordered chain
// of relay-id hops coxswain dials OUT through to reach every node's control
// plane, hiding the controller's origin (DESIGN §3). Exactly one path is Active
// at a time — the fleet-wide control route; swapping the active path (via
// SetActiveControlPath) reroutes the whole control plane live, no re-onboarding.
// Empty Hops = direct. This is decoupled from server onboarding/deployment,
// which carries no routing state.
type ControlPath struct {
	ID   string
	Name string
	// Hops is the ordered relay-id chain (hop 1 closest to coxswain, the last hop
	// reaches the node). Empty = direct.
	Hops []string
	// Active marks the single fleet-wide active control path.
	Active    bool
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

const controlPathColumns = `id, name, hops, is_active, version, created_at, updated_at`

// hopsToCSV / hopsFromCSV (de)serialize the ordered relay-id hop list to the
// single `hops` column. Empty list ⇄ empty string (direct).
func hopsToCSV(hops []string) string { return strings.Join(hops, ",") }

func hopsFromCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// CreateControlPath inserts a new control path. ID defaults if empty, Version is
// set to 1. A new path is created INACTIVE — activate it with
// SetActiveControlPath. The stored ControlPath is returned.
func CreateControlPath(ctx context.Context, db *sql.DB, c ControlPath) (ControlPath, error) {
	if c.Name == "" {
		return ControlPath{}, fmt.Errorf("create control path: name is required")
	}
	if c.ID == "" {
		c.ID = idgen.New("cpath")
	}
	c.Active = false // activation is an explicit, separate step (one active at a time)
	now := time.Now().UTC()
	c.Version = 1
	c.CreatedAt, c.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO control_paths (`+controlPathColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, hopsToCSV(c.Hops), 0, c.Version, c.CreatedAt, c.UpdatedAt)
	if err != nil {
		return ControlPath{}, fmt.Errorf("create control path: %w", err)
	}
	return c, nil
}

// GetControlPath returns the control path with the given ID, or ErrNotFound.
func GetControlPath(ctx context.Context, db *sql.DB, id string) (ControlPath, error) {
	row := db.QueryRowContext(ctx, `SELECT `+controlPathColumns+` FROM control_paths WHERE id = ?`, id)
	c, err := scanControlPath(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlPath{}, ErrNotFound
	}
	return c, err
}

// ListControlPaths returns every control path, oldest first.
func ListControlPaths(ctx context.Context, db *sql.DB) ([]ControlPath, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+controlPathColumns+` FROM control_paths ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list control paths: %w", err)
	}
	defer rows.Close()

	var out []ControlPath
	for rows.Next() {
		c, err := scanControlPath(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetActiveControlPath returns the single fleet-wide active control path, or
// ErrNotFound when none is active (which the router treats as direct).
func GetActiveControlPath(ctx context.Context, db *sql.DB) (ControlPath, error) {
	row := db.QueryRowContext(ctx, `SELECT `+controlPathColumns+` FROM control_paths WHERE is_active = 1`)
	c, err := scanControlPath(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ControlPath{}, ErrNotFound
	}
	return c, err
}

// ActiveControlPathHops returns the ordered relay-id hops of the fleet-wide
// active control path, or nil (direct) when none is active. This is the single
// source of truth for control-plane routing — every control dial resolves
// through here, so swapping the active path reroutes the whole fleet at once.
func ActiveControlPathHops(ctx context.Context, db *sql.DB) []string {
	c, err := GetActiveControlPath(ctx, db)
	if err != nil {
		return nil
	}
	return c.Hops
}

// UpdateControlPath writes name + hops back under optimistic concurrency: it
// succeeds only if c.Version matches the stored row. The active flag is NOT
// changed here (use SetActiveControlPath). A stale version yields
// ErrStaleVersion; a missing row yields ErrNotFound.
func UpdateControlPath(ctx context.Context, db *sql.DB, c ControlPath) (ControlPath, error) {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE control_paths SET name = ?, hops = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		c.Name, hopsToCSV(c.Hops), now, c.ID, c.Version)
	if err != nil {
		return ControlPath{}, fmt.Errorf("update control path: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return ControlPath{}, err
	}
	if affected == 0 {
		if _, gErr := GetControlPath(ctx, db, c.ID); errors.Is(gErr, ErrNotFound) {
			return ControlPath{}, ErrNotFound
		}
		return ControlPath{}, ErrStaleVersion
	}
	c.Version++
	c.UpdatedAt = now
	return c, nil
}

// SetActiveControlPath makes id the single fleet-wide active control path,
// deactivating whichever was active before — atomically, so the control plane
// is never left with two active routes or (mid-swap) violating the one-active
// index. A missing id yields ErrNotFound.
func SetActiveControlPath(ctx context.Context, db *sql.DB, id string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("set active control path: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	// Deactivate the current active first (so the partial-unique index never sees
	// two active rows), then activate the target.
	if _, err := tx.ExecContext(ctx,
		`UPDATE control_paths SET is_active = 0, version = version + 1, updated_at = ?
		 WHERE is_active = 1`, now); err != nil {
		return fmt.Errorf("set active control path: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE control_paths SET is_active = 1, version = version + 1, updated_at = ?
		 WHERE id = ?`, now, id)
	if err != nil {
		return fmt.Errorf("set active control path: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// DeleteControlPath removes a control path. A missing row yields ErrNotFound.
// (Deleting the active path leaves the fleet with no active route → direct.)
func DeleteControlPath(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM control_paths WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete control path: %w", err)
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

func scanControlPath(s rowScanner) (ControlPath, error) {
	var (
		c    ControlPath
		hops string
		act  int
	)
	if err := s.Scan(&c.ID, &c.Name, &hops, &act, &c.Version, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return ControlPath{}, err
	}
	c.Hops = hopsFromCSV(hops)
	c.Active = act == 1
	return c, nil
}
