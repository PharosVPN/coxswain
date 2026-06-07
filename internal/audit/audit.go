// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package audit is coxswain's first-class audit log: a durable record of every
// management mutation — who did what, to what, from where, and whether it
// succeeded. Each Log call writes a row to the audit_log table AND emits a
// structured slog line, so the same event lands in the database (for querying)
// and in journald (for live tailing). API handlers and CLI commands both call
// Log on success and failure.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// Actor-kind constants.
const (
	KindToken   = "token"   // a bearer API token
	KindSession = "session" // an admin session cookie
	KindCLI     = "cli"     // a local `cox` command (the OS user)
)

// Result constants.
const (
	ResultOK    = "ok"
	ResultError = "error"
)

// Entry is one audit record. Result defaults to ResultOK when empty; pass an
// Err to mark a failure (Log derives Result=error and the message from it).
type Entry struct {
	Actor      string         // token name, session user, or CLI OS user
	ActorKind  string         // KindToken | KindSession | KindCLI
	Action     string         // dotted verb, e.g. "node.add", "profile.create"
	TargetType string         // e.g. "node", "device", "path", "token"
	TargetID   string         // the affected record id (when known)
	SourceIP   string         // request source IP for API calls; empty for CLI
	Detail     map[string]any // small action-specific context (JSON-encoded)
	Result     string         // ResultOK | ResultError (derived from Err if set)
	Err        error          // non-nil marks the action a failure
}

// Log writes entry to the audit_log table and emits a structured slog line. A
// non-nil entry.Err makes the row result='error' with the error message. The
// DB write is the source of truth: if it fails, Log returns that error (callers
// generally ignore it — auditing must never break the mutation it records — but
// it is surfaced for tests and diagnostics). The slog line is always emitted.
func Log(ctx context.Context, db *sql.DB, entry Entry) error {
	now := time.Now().UTC()

	result := entry.Result
	errMsg := ""
	if entry.Err != nil {
		result = ResultError
		errMsg = entry.Err.Error()
	}
	if result == "" {
		result = ResultOK
	}

	detail := ""
	if len(entry.Detail) > 0 {
		if b, err := json.Marshal(entry.Detail); err == nil {
			detail = string(b)
		}
	}

	// Structured line first, so the event reaches journald even if the DB write
	// below fails. Failures log at warn, successes at info.
	attrs := []any{
		"actor", entry.Actor,
		"actor_kind", entry.ActorKind,
		"action", entry.Action,
		"target_type", entry.TargetType,
		"target_id", entry.TargetID,
		"source_ip", entry.SourceIP,
		"result", result,
	}
	if errMsg != "" {
		attrs = append(attrs, "error", errMsg)
	}
	if result == ResultError {
		slog.Warn("audit", attrs...)
	} else {
		slog.Info("audit", attrs...)
	}

	id := idgen.New("aud")
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_log
		 (id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, now, entry.Actor, entry.ActorKind, entry.Action,
		entry.TargetType, entry.TargetID, entry.SourceIP, detail, result, errMsg)
	if err != nil {
		return fmt.Errorf("audit: write log: %w", err)
	}
	return nil
}

// Record is a stored audit row, as returned by Query.
type Record struct {
	ID         string         `json:"id"`
	At         time.Time      `json:"at"`
	Actor      string         `json:"actor"`
	ActorKind  string         `json:"actor_kind"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	SourceIP   string         `json:"source_ip"`
	Detail     map[string]any `json:"detail,omitempty"`
	Result     string         `json:"result"`
	Error      string         `json:"error,omitempty"`
}

// Filter narrows a Query. Zero-value fields are not applied. Limit defaults to
// DefaultLimit and is capped at MaxLimit.
type Filter struct {
	Actor    string
	Action   string
	TargetID string
	Since    time.Time
	Until    time.Time
	Limit    int
}

// Query limits.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Query returns audit records matching the filter, newest first.
func Query(ctx context.Context, db *sql.DB, f Filter) ([]Record, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	q := `SELECT id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error
	      FROM audit_log WHERE 1=1`
	var args []any
	if f.Actor != "" {
		q += " AND actor = ?"
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		q += " AND action = ?"
		args = append(args, f.Action)
	}
	if f.TargetID != "" {
		q += " AND target_id = ?"
		args = append(args, f.TargetID)
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
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var (
			r      Record
			detail string
		)
		if err := rows.Scan(&r.ID, &r.At, &r.Actor, &r.ActorKind, &r.Action,
			&r.TargetType, &r.TargetID, &r.SourceIP, &detail, &r.Result, &r.Error); err != nil {
			return nil, err
		}
		if detail != "" {
			_ = json.Unmarshal([]byte(detail), &r.Detail)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Purge deletes audit rows older than `days` days. days <= 0 is a no-op (audit
// retention disabled). It returns the number of rows removed.
func Purge(ctx context.Context, db *sql.DB, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	res, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("audit: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SourceIP extracts the client IP from an HTTP request: the RemoteAddr with its
// port stripped (coxswain binds localhost and sits behind no proxy, so we do not
// trust X-Forwarded-For).
func SourceIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// contextKey is private so only this package can set/read the request actor.
type contextKey int

const actorKey contextKey = iota

// Actor identifies who is performing an action, for the audit trail.
type Actor struct {
	Name string // token name or session user
	Kind string // KindToken | KindSession | KindCLI
}

// WithActor returns a context carrying the actor, for handlers to read via
// ActorFrom. The API auth middleware sets this once it resolves the request.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey, a)
}

// ActorFrom returns the actor placed by WithActor, or a zero Actor if none.
func ActorFrom(ctx context.Context) Actor {
	a, _ := ctx.Value(actorKey).(Actor)
	return a
}
