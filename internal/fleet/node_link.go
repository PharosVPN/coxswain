// SPDX-License-Identifier: AGPL-3.0-or-later
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

// NodeLink errors.
var (
	// ErrSelfLink is returned when an edge's entry and exit are the same node.
	ErrSelfLink = errors.New("fleet: a node link cannot loop a node to itself")
	// ErrLinkExists is returned when an entry→exit edge already exists.
	ErrLinkExists = errors.New("fleet: node link already exists for this entry and exit")
)

// Inner-link resource bases. Each link on an entry node is assigned a distinct
// index; the inner interface, listen port, fwmark and routing-table id are all
// derived from it so they never collide on that node. The port base sits above
// the client port (443) and clear of the endpoint-rotation range.
const (
	innerPortBase  = 51820
	markTableBase  = 7100
	innerIfacePrec = "awg"
)

// NodeLink is one entry→exit edge of the node-cascade graph (the `node_links`
// table, DESIGN §3 decision 18): an inner AmneziaWG link the entry node dials
// to the exit. coxswain allocates the entry-side resources and coordinates the
// link over the control plane; the row is the source of truth for the edge.
type NodeLink struct {
	ID             string
	EntryNodeID    string
	ExitNodeID     string
	InnerInterface string
	ListenPort     int
	Fwmark         int
	TableID        int
	PresharedKey   string
	ConfigRevision int64
	Status         string
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const nodeLinkColumns = `id, entry_node_id, exit_node_id, inner_interface,
	listen_port, fwmark, table_id, preshared_key, config_revision, status,
	version, created_at, updated_at`

// CreateNodeLink allocates the entry-side resources for a new entry→exit edge
// and inserts it. The inner interface name, listen port, fwmark and table id
// are derived from the smallest index free on the entry node, so concurrent
// links never collide (the table's UNIQUE constraints are the backstop).
func CreateNodeLink(ctx context.Context, db *sql.DB, entryNodeID, exitNodeID, presharedKey string) (NodeLink, error) {
	if entryNodeID == exitNodeID {
		return NodeLink{}, ErrSelfLink
	}
	existing, err := ListNodeLinksByEntry(ctx, db, entryNodeID)
	if err != nil {
		return NodeLink{}, err
	}
	usedIface := make(map[string]bool, len(existing))
	for _, l := range existing {
		if l.ExitNodeID == exitNodeID {
			return NodeLink{}, ErrLinkExists
		}
		usedIface[l.InnerInterface] = true
	}
	idx := 0
	for usedIface[fmt.Sprintf("%s%d", innerIfacePrec, idx+1)] {
		idx++
	}

	now := time.Now().UTC()
	nl := NodeLink{
		ID:             idgen.New("nlk"),
		EntryNodeID:    entryNodeID,
		ExitNodeID:     exitNodeID,
		InnerInterface: fmt.Sprintf("%s%d", innerIfacePrec, idx+1),
		ListenPort:     innerPortBase + idx,
		Fwmark:         markTableBase + idx,
		TableID:        markTableBase + idx,
		PresharedKey:   presharedKey,
		ConfigRevision: 0,
		Status:         "pending",
		Version:        1,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO node_links (`+nodeLinkColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nl.ID, nl.EntryNodeID, nl.ExitNodeID, nl.InnerInterface, nl.ListenPort,
		nl.Fwmark, nl.TableID, nl.PresharedKey, nl.ConfigRevision, nl.Status,
		nl.Version, nl.CreatedAt, nl.UpdatedAt)
	if err != nil {
		return NodeLink{}, fmt.Errorf("create node link: %w", err)
	}
	return nl, nil
}

// GetNodeLink returns one link by id.
func GetNodeLink(ctx context.Context, db *sql.DB, id string) (NodeLink, error) {
	links, err := queryNodeLinks(ctx, db, `WHERE id = ?`, id)
	if err != nil {
		return NodeLink{}, err
	}
	if len(links) == 0 {
		return NodeLink{}, ErrNotFound
	}
	return links[0], nil
}

// GetNodeLinkByEdge returns the link for a specific entry→exit pair.
func GetNodeLinkByEdge(ctx context.Context, db *sql.DB, entryNodeID, exitNodeID string) (NodeLink, error) {
	links, err := queryNodeLinks(ctx, db,
		`WHERE entry_node_id = ? AND exit_node_id = ?`, entryNodeID, exitNodeID)
	if err != nil {
		return NodeLink{}, err
	}
	if len(links) == 0 {
		return NodeLink{}, ErrNotFound
	}
	return links[0], nil
}

// ListNodeLinks returns every edge, oldest first.
func ListNodeLinks(ctx context.Context, db *sql.DB) ([]NodeLink, error) {
	return queryNodeLinks(ctx, db, `ORDER BY created_at`)
}

// ListNodeLinksByEntry returns every edge leaving an entry node.
func ListNodeLinksByEntry(ctx context.Context, db *sql.DB, entryNodeID string) ([]NodeLink, error) {
	return queryNodeLinks(ctx, db, `WHERE entry_node_id = ? ORDER BY created_at`, entryNodeID)
}

// DeleteNodeLink removes an edge. Removing a missing edge is not an error.
func DeleteNodeLink(ctx context.Context, db *sql.DB, id string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM node_links WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete node link: %w", err)
	}
	return nil
}

// SetNodeLinkStatus updates a link's status with the optimistic-concurrency
// guard. A stale version returns ErrStaleVersion; a missing row ErrNotFound.
func SetNodeLinkStatus(ctx context.Context, db *sql.DB, id, status string, version int) error {
	res, err := db.ExecContext(ctx,
		`UPDATE node_links SET status = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		status, time.Now().UTC(), id, version)
	if err != nil {
		return fmt.Errorf("update node link status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := GetNodeLink(ctx, db, id); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return ErrStaleVersion
	}
	return nil
}

// NextNodeLinkConfigRevision atomically increments and returns a link's
// ConfigureInnerLink revision — the same monotonic-counter idiom as
// NextNodeConfigRevision.
func NextNodeLinkConfigRevision(ctx context.Context, db *sql.DB, id string) (int64, error) {
	var rev int64
	err := db.QueryRowContext(ctx,
		`UPDATE node_links SET config_revision = config_revision + 1, updated_at = ?
		 WHERE id = ? RETURNING config_revision`,
		time.Now().UTC(), id).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("next node link revision: %w", err)
	}
	return rev, nil
}

func queryNodeLinks(ctx context.Context, db *sql.DB, where string, args ...any) ([]NodeLink, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+nodeLinkColumns+` FROM node_links `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list node links: %w", err)
	}
	defer rows.Close()

	var out []NodeLink
	for rows.Next() {
		var l NodeLink
		if err := rows.Scan(&l.ID, &l.EntryNodeID, &l.ExitNodeID, &l.InnerInterface,
			&l.ListenPort, &l.Fwmark, &l.TableID, &l.PresharedKey, &l.ConfigRevision,
			&l.Status, &l.Version, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
