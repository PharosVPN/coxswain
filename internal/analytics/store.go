// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// Alert is a stored alerts row, as returned by Query and the upsert.
type Alert struct {
	ID        string         `json:"id"`
	At        time.Time      `json:"at"`
	Kind      string         `json:"kind"`
	Severity  string         `json:"severity"`
	DeviceID  string         `json:"device_id,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	NodeID    string         `json:"node_id,omitempty"`
	SourceIPs []string       `json:"source_ips"`
	Detail    map[string]any `json:"detail,omitempty"`
	Status    string         `json:"status"`
	DedupKey  string         `json:"dedup_key,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// upsertAlert writes a Finding to the alerts table, deduplicating by DedupKey.
// While an alert with the same key is still OPEN, the detection is refreshed in
// place — updated_at bumped, at advanced to the new event time, source_ips and
// detail merged — and isNew is false, so a persistent condition does not spam a
// new alert on every sweep. With no open alert for the key, a fresh open alert
// is inserted and isNew is true (which the caller fans out to the live hub). The
// partial unique index on (dedup_key) WHERE status='open' enforces at most one
// open row per key. Once an alert is acknowledged/resolved, the key is free to
// open a new alert again — a recurrence after the operator handled the prior one.
func upsertAlert(ctx context.Context, db *sql.DB, f Finding, now time.Time) (Alert, bool, error) {
	at := f.At
	if at.IsZero() {
		at = now
	}

	var (
		existingID                  string
		existingSrc, existingDetail string
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, source_ips, detail
		FROM alerts
		WHERE dedup_key = ? AND status = ?
		LIMIT 1`, f.DedupKey, StatusOpen).
		Scan(&existingID, &existingSrc, &existingDetail)

	switch {
	case err == sql.ErrNoRows:
		// No open alert for this key — insert a fresh one.
		return insertAlert(ctx, db, f, at, now)
	case err != nil:
		return Alert{}, false, fmt.Errorf("analytics: dedup lookup: %w", err)
	}

	// An open alert exists — refresh it in place rather than duplicating.
	merged := mergeSourceIPs(existingSrc, f.SourceIPs)
	detail := mergeDetail(existingDetail, f.Detail, now)
	srcJSON, _ := json.Marshal(merged)
	detailJSON, _ := json.Marshal(detail)

	if _, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET at = ?, source_ips = ?, detail = ?, updated_at = ?
		WHERE id = ?`,
		at.UTC(), string(srcJSON), string(detailJSON), now.UTC(), existingID); err != nil {
		return Alert{}, false, fmt.Errorf("analytics: refresh alert: %w", err)
	}
	return Alert{ID: existingID}, false, nil
}

// insertAlert writes a brand-new open alert and returns it with isNew=true.
func insertAlert(ctx context.Context, db *sql.DB, f Finding, at, now time.Time) (Alert, bool, error) {
	id := idgen.New("alr")
	src := dedupSorted(f.SourceIPs)
	srcJSON, _ := json.Marshal(src)
	detail := f.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, _ := json.Marshal(detail)

	if _, err := db.ExecContext(ctx, `
		INSERT INTO alerts
		(id, at, kind, severity, device_id, user_id, node_id, source_ips, detail, status, dedup_key, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, at.UTC(), f.Kind, f.Severity,
		nullable(f.DeviceID), nullable(f.UserID), nullable(f.NodeID),
		string(srcJSON), string(detailJSON), StatusOpen, f.DedupKey, now.UTC(), now.UTC()); err != nil {
		return Alert{}, false, fmt.Errorf("analytics: insert alert: %w", err)
	}

	return Alert{
		ID: id, At: at.UTC(), Kind: f.Kind, Severity: f.Severity,
		DeviceID: f.DeviceID, UserID: f.UserID, NodeID: f.NodeID,
		SourceIPs: src, Detail: detail, Status: StatusOpen, DedupKey: f.DedupKey,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, true, nil
}

// mergeSourceIPs unions a stored JSON IP array with new IPs, sorted + deduped.
func mergeSourceIPs(storedJSON string, add []string) []string {
	var stored []string
	if storedJSON != "" {
		_ = json.Unmarshal([]byte(storedJSON), &stored)
	}
	return dedupSorted(append(stored, add...))
}

// mergeDetail merges fresh evidence onto stored evidence: new keys win, and a
// last_seen timestamp records the most recent refresh, so a persistent alert's
// detail tracks the latest observation without losing the original.
func mergeDetail(storedJSON string, fresh map[string]any, now time.Time) map[string]any {
	out := map[string]any{}
	if storedJSON != "" {
		_ = json.Unmarshal([]byte(storedJSON), &out)
	}
	for k, v := range fresh {
		out[k] = v
	}
	out["last_seen"] = now.UTC().Format(time.RFC3339)
	return out
}

// dedupSorted returns the unique, sorted, non-empty members of in.
func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// nullable converts an empty string to a SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Query limits.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Filter narrows a Query. Zero-value fields are not applied. Limit defaults to
// DefaultLimit and is capped at MaxLimit.
type Filter struct {
	Status   string
	Kind     string
	DeviceID string
	Severity string
	Since    time.Time
	Limit    int
}

// Query returns alerts matching the filter, newest-first.
func Query(ctx context.Context, db *sql.DB, f Filter) ([]Alert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	q := `SELECT id, at, kind, severity, device_id, user_id, node_id,
	             source_ips, detail, status, dedup_key, created_at, updated_at
	      FROM alerts WHERE 1=1`
	var args []any
	if f.Status != "" {
		q += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Kind != "" {
		q += " AND kind = ?"
		args = append(args, f.Kind)
	}
	if f.DeviceID != "" {
		q += " AND device_id = ?"
		args = append(args, f.DeviceID)
	}
	if f.Severity != "" {
		q += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if !f.Since.IsZero() {
		q += " AND at >= ?"
		args = append(args, f.Since.UTC())
	}
	q += " ORDER BY at DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("analytics: query: %w", err)
	}
	defer rows.Close()

	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns a single alert by id, or sql.ErrNoRows if absent.
func Get(ctx context.Context, db *sql.DB, id string) (Alert, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, at, kind, severity, device_id, user_id, node_id,
		       source_ips, detail, status, dedup_key, created_at, updated_at
		FROM alerts WHERE id = ?`, id)
	return scanAlert(row)
}

// SetStatus updates an alert's status (e.g. acknowledge/resolve) and bumps
// updated_at. It returns sql.ErrNoRows if the id does not exist.
func SetStatus(ctx context.Context, db *sql.DB, id, status string, now time.Time) error {
	res, err := db.ExecContext(ctx,
		`UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?`,
		status, now.UTC(), id)
	if err != nil {
		return fmt.Errorf("analytics: set status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// resolveOpenByDedup marks any open alert with the given dedup_key as resolved.
// It is the auto-resolve primitive: a rule whose condition has cleared (e.g.
// fleet_health when a node returns to active) calls this so the open alert does
// not linger. It is a no-op when no open alert exists for the key. updated_at is
// bumped to now on whatever it closes.
func resolveOpenByDedup(ctx context.Context, db *sql.DB, dedupKey string, now time.Time) error {
	if dedupKey == "" {
		return nil
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE alerts SET status = ?, updated_at = ? WHERE dedup_key = ? AND status = ?`,
		StatusResolved, now.UTC(), dedupKey, StatusOpen); err != nil {
		return fmt.Errorf("analytics: auto-resolve %s: %w", dedupKey, err)
	}
	return nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanAlert(s scanner) (Alert, error) {
	var (
		a                        Alert
		deviceID, userID, nodeID sql.NullString
		srcJSON, detailJSON      string
	)
	if err := s.Scan(&a.ID, &a.At, &a.Kind, &a.Severity, &deviceID, &userID, &nodeID,
		&srcJSON, &detailJSON, &a.Status, &a.DedupKey, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return Alert{}, err
	}
	a.DeviceID, a.UserID, a.NodeID = deviceID.String, userID.String, nodeID.String
	a.SourceIPs = []string{}
	if srcJSON != "" {
		_ = json.Unmarshal([]byte(srcJSON), &a.SourceIPs)
	}
	if detailJSON != "" {
		_ = json.Unmarshal([]byte(detailJSON), &a.Detail)
	}
	return a, nil
}

// Purge deletes alerts older than `days` days. days <= 0 is a no-op. It returns
// the number of rows removed.
func Purge(ctx context.Context, db *sql.DB, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	res, err := db.ExecContext(ctx, `DELETE FROM alerts WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("analytics: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
