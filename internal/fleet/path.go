// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// MaxPathHops caps a data-plane path at this many inner-link segments — i.e. a
// path may have at most MaxPathHops+1 nodes (entry → [mid…] → exit). It is a
// code constant, not a config knob: one line to raise once 2-hop is proven (the
// node-cascade work iterates by depth anyway). DESIGN §3 hop limit.
const MaxPathHops = 2

// ErrInvalidPath is returned when a path's hop list is malformed (too few/many
// hops, a repeated node, or an adjacent self-loop). Callers map it to 400.
var ErrInvalidPath = errors.New("fleet: invalid path")

// Path is a named, ordered data plane (the `paths` table): entry → [mid] → exit.
// The hop list (path_hops) is the source of truth; the inner-link segments
// between consecutive hops are node_links rows the cascade coordinator
// materializes. A device binds to a path (device_exits), not a bare link.
type Path struct {
	ID        string
	Name      string
	Color     string
	Status    string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PathHop is one node in a path's ordered chain (hop 0 = entry, last = exit).
type PathHop struct {
	PathID   string
	HopIndex int
	NodeID   string
}

const pathColumns = `id, name, color, status, version, created_at, updated_at`

// CreatePath inserts a path and its ordered hops in one transaction. nodeIDs
// must hold 2..MaxPathHops+1 distinct nodes with no two adjacent equal. The
// stored Path (status pending) is returned.
func CreatePath(ctx context.Context, db *sql.DB, name, color string, nodeIDs []string) (Path, error) {
	if len(nodeIDs) < 2 {
		return Path{}, fmt.Errorf("%w: a path needs at least an entry and an exit", ErrInvalidPath)
	}
	if len(nodeIDs) > MaxPathHops+1 {
		return Path{}, fmt.Errorf("%w: a path may have at most %d hops (%d nodes)", ErrInvalidPath, MaxPathHops, MaxPathHops+1)
	}
	seen := make(map[string]bool, len(nodeIDs))
	for i, id := range nodeIDs {
		if id == "" {
			return Path{}, fmt.Errorf("%w: empty node id at hop %d", ErrInvalidPath, i)
		}
		if seen[id] {
			return Path{}, fmt.Errorf("%w: node %s appears more than once", ErrInvalidPath, id)
		}
		seen[id] = true
	}

	now := time.Now().UTC()
	p := Path{
		ID:        idgen.New("pth"),
		Name:      name,
		Color:     color,
		Status:    StatusPending,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Path{}, fmt.Errorf("create path: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO paths (`+pathColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Color, p.Status, p.Version, p.CreatedAt, p.UpdatedAt); err != nil {
		return Path{}, fmt.Errorf("create path: %w", err)
	}
	for i, nodeID := range nodeIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO path_hops (path_id, hop_index, node_id) VALUES (?, ?, ?)`,
			p.ID, i, nodeID); err != nil {
			return Path{}, fmt.Errorf("create path hop %d: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Path{}, fmt.Errorf("create path: %w", err)
	}
	return p, nil
}

// GetPath returns one path by id, or ErrNotFound.
func GetPath(ctx context.Context, db *sql.DB, id string) (Path, error) {
	row := db.QueryRowContext(ctx, `SELECT `+pathColumns+` FROM paths WHERE id = ?`, id)
	p, err := scanPath(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Path{}, ErrNotFound
	}
	return p, err
}

// ListPaths returns every path, oldest first.
func ListPaths(ctx context.Context, db *sql.DB) ([]Path, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+pathColumns+` FROM paths ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list paths: %w", err)
	}
	defer rows.Close()
	var out []Path
	for rows.Next() {
		p, err := scanPath(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListPathHops returns a path's hops in order (hop 0 = entry, last = exit).
func ListPathHops(ctx context.Context, db *sql.DB, pathID string) ([]PathHop, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT path_id, hop_index, node_id FROM path_hops WHERE path_id = ? ORDER BY hop_index`, pathID)
	if err != nil {
		return nil, fmt.Errorf("list path hops: %w", err)
	}
	defer rows.Close()
	var out []PathHop
	for rows.Next() {
		var h PathHop
		if err := rows.Scan(&h.PathID, &h.HopIndex, &h.NodeID); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetPathStatus updates a path's status with the optimistic-concurrency guard
// (the same idiom as SetNodeLinkStatus). A stale version yields ErrStaleVersion;
// a missing row ErrNotFound.
func SetPathStatus(ctx context.Context, db *sql.DB, id, status string, version int) error {
	res, err := db.ExecContext(ctx,
		`UPDATE paths SET status = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		status, time.Now().UTC(), id, version)
	if err != nil {
		return fmt.Errorf("set path status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, gErr := GetPath(ctx, db, id); errors.Is(gErr, ErrNotFound) {
			return ErrNotFound
		}
		return ErrStaleVersion
	}
	return nil
}

// SetPathColor sets a path's map colour (a hex string, or empty to fall back to
// the auto palette). Cosmetic — no concurrency guard.
func SetPathColor(ctx context.Context, db *sql.DB, id, color string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE paths SET color = ?, updated_at = ? WHERE id = ?`,
		color, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set path color: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePath removes a path (its hops cascade). A missing row yields ErrNotFound.
func DeletePath(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM paths WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete path: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPathsByEdge returns the ids of every path whose ordered hops contain the
// directed edge entry→exit as a consecutive pair — the set whose devices the
// edge (a shared node_link) carries. Used to union devices across paths during
// reconcile.
func ListPathsByEdge(ctx context.Context, db *sql.DB, entryNodeID, exitNodeID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT a.path_id
		 FROM path_hops a
		 JOIN path_hops b ON b.path_id = a.path_id AND b.hop_index = a.hop_index + 1
		 WHERE a.node_id = ? AND b.node_id = ?`, entryNodeID, exitNodeID)
	if err != nil {
		return nil, fmt.Errorf("list paths by edge: %w", err)
	}
	defer rows.Close()
	return scanIDs(rows)
}

// ListPathIDsContainingNode returns the ids of every path that has the node as
// any hop (entry, mid, or exit).
func ListPathIDsContainingNode(ctx context.Context, db *sql.DB, nodeID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT path_id FROM path_hops WHERE node_id = ?`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("list paths containing node: %w", err)
	}
	defer rows.Close()
	return scanIDs(rows)
}

// CountPathsUsingLink returns how many paths traverse the edge that a node_link
// represents (its entry→exit pair as a consecutive hop pair) — the ref-count
// that gates tearing the inner link down on DeprovisionPath.
func CountPathsUsingLink(ctx context.Context, db *sql.DB, linkID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT a.path_id)
		FROM node_links nl
		JOIN path_hops a ON a.node_id = nl.entry_node_id
		JOIN path_hops b ON b.path_id = a.path_id
		     AND b.hop_index = a.hop_index + 1
		     AND b.node_id = nl.exit_node_id
		WHERE nl.id = ?`, linkID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count paths using link: %w", err)
	}
	return n, nil
}

func scanPath(s rowScanner) (Path, error) {
	var p Path
	err := s.Scan(&p.ID, &p.Name, &p.Color, &p.Status, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Path{}, err
	}
	return p, nil
}

func scanIDs(rows *sql.Rows) ([]string, error) {
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
