// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Query limits.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Record is one stored session event, as returned by Query.
type Record struct {
	ID             string    `json:"id"`
	At             time.Time `json:"at"`
	NodeID         string    `json:"node_id,omitempty"`
	PeerID         string    `json:"peer_id,omitempty"`
	DeviceID       string    `json:"device_id,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
	EventType      string    `json:"event_type"`
	SourceIP       string    `json:"source_ip,omitempty"`
	SourceEndpoint string    `json:"source_endpoint,omitempty"`
	RxBytes        uint64    `json:"rx_bytes"`
	TxBytes        uint64    `json:"tx_bytes"`
	// Reason annotates why the event was written: empty for a node-reported
	// event, "stream-lost" for a synthetic disconnect the controller wrote when
	// the node's stream dropped (LOW-14).
	Reason string `json:"reason,omitempty"`
}

// Filter narrows a Query. Zero-value fields are not applied. Limit defaults to
// DefaultLimit and is capped at MaxLimit.
type Filter struct {
	DeviceID string
	UserID   string
	NodeID   string
	SourceIP string
	Since    time.Time
	Until    time.Time
	Limit    int
}

// Query returns connection_events matching the filter, newest first.
func Query(ctx context.Context, db *sql.DB, f Filter) ([]Record, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	q := `SELECT id, at, node_id, peer_id, device_id, user_id, protocol,
	             event_type, source_ip, source_endpoint, rx_bytes, tx_bytes, reason
	      FROM connection_events WHERE 1=1`
	var args []any
	if f.DeviceID != "" {
		q += " AND device_id = ?"
		args = append(args, f.DeviceID)
	}
	if f.UserID != "" {
		q += " AND user_id = ?"
		args = append(args, f.UserID)
	}
	if f.NodeID != "" {
		q += " AND node_id = ?"
		args = append(args, f.NodeID)
	}
	if f.SourceIP != "" {
		q += " AND source_ip = ?"
		args = append(args, f.SourceIP)
	}
	if !f.Since.IsZero() {
		q += " AND at >= ?"
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		q += " AND at <= ?"
		args = append(args, f.Until.UTC())
	}
	q += " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("monitor: query: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var (
			r                Record
			deviceID, userID sql.NullString
		)
		if err := rows.Scan(&r.ID, &r.At, &r.NodeID, &r.PeerID, &deviceID, &userID,
			&r.Protocol, &r.EventType, &r.SourceIP, &r.SourceEndpoint, &r.RxBytes, &r.TxBytes, &r.Reason); err != nil {
			return nil, err
		}
		r.DeviceID = deviceID.String
		r.UserID = userID.String
		out = append(out, r)
	}
	return out, rows.Err()
}
