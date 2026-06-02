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

// Relay kinds (the `relays` table). The embedded relay runs in coxswain's own
// process; a remote relay is a beacon binary coxswain enrols over SSH and reaches
// by dialling out to its reverse-tunnel listener (DESIGN §2).
const (
	RelayKindEmbedded = "embedded"
	RelayKindRemote   = "remote"
)

// Relay is one entry in the relay tier (the `relays` table).
type Relay struct {
	ID   string
	Name string
	Kind string
	// Endpoint is the reverse-tunnel address coxswain dials for a remote relay.
	// Empty for the embedded relay.
	Endpoint string
	// EgressEndpoint is the relay's `beacon egress` tunnel address coxswain dials
	// to route its control-plane connections (gRPC + SSH) to nodes through this
	// relay (DESIGN §3, decision 19). Empty means the relay carries no egress.
	EgressEndpoint string
	Status         string
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const relayColumns = `id, name, kind, endpoint, egress_endpoint, status, version, created_at, updated_at`

// CreateRelay inserts a new relay. ID and Status are filled in if empty,
// Version is set to 1. The stored Relay is returned.
func CreateRelay(ctx context.Context, db *sql.DB, r Relay) (Relay, error) {
	if r.Kind != RelayKindEmbedded && r.Kind != RelayKindRemote {
		return Relay{}, fmt.Errorf("create relay: invalid kind %q", r.Kind)
	}
	if r.ID == "" {
		r.ID = idgen.New("rly")
	}
	if r.Status == "" {
		r.Status = StatusPending
	}
	now := time.Now().UTC()
	r.Version = 1
	r.CreatedAt, r.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO relays (`+relayColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Kind, r.Endpoint, r.EgressEndpoint, r.Status, r.Version, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return Relay{}, fmt.Errorf("create relay: %w", err)
	}
	return r, nil
}

// GetRelay returns the relay with the given ID, or ErrNotFound.
func GetRelay(ctx context.Context, db *sql.DB, id string) (Relay, error) {
	row := db.QueryRowContext(ctx, `SELECT `+relayColumns+` FROM relays WHERE id = ?`, id)
	r, err := scanRelay(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, ErrNotFound
	}
	return r, err
}

// ListRelays returns every relay, oldest first.
func ListRelays(ctx context.Context, db *sql.DB) ([]Relay, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+relayColumns+` FROM relays ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list relays: %w", err)
	}
	defer rows.Close()

	var out []Relay
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRelay writes r back under optimistic concurrency: the update succeeds
// only if r.Version matches the stored row. On success the version is bumped
// and the refreshed Relay returned. A stale version yields ErrStaleVersion; a
// missing row yields ErrNotFound.
func UpdateRelay(ctx context.Context, db *sql.DB, r Relay) (Relay, error) {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE relays SET name = ?, kind = ?, endpoint = ?, egress_endpoint = ?, status = ?,
		        version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		r.Name, r.Kind, r.Endpoint, r.EgressEndpoint, r.Status, now, r.ID, r.Version)
	if err != nil {
		return Relay{}, fmt.Errorf("update relay: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Relay{}, err
	}
	if affected == 0 {
		if _, gErr := GetRelay(ctx, db, r.ID); errors.Is(gErr, ErrNotFound) {
			return Relay{}, ErrNotFound
		}
		return Relay{}, ErrStaleVersion
	}
	r.Version++
	r.UpdatedAt = now
	return r, nil
}

// DeleteRelay removes a relay. A missing row yields ErrNotFound.
func DeleteRelay(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM relays WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete relay: %w", err)
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

func scanRelay(s rowScanner) (Relay, error) {
	var r Relay
	err := s.Scan(&r.ID, &r.Name, &r.Kind, &r.Endpoint, &r.EgressEndpoint, &r.Status,
		&r.Version, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return Relay{}, err
	}
	return r, nil
}
