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
	"sync"
	"sync/atomic"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// writeFailures counts audit rows whose DB INSERT failed (the slog line was
// still emitted). It is a process-lifetime counter for a future metric — an
// audit-loss gauge the operator can alert on. Read it with WriteFailures.
var writeFailures atomic.Int64

// WriteFailures returns how many audit-row DB writes have failed this process —
// every one is a silently-uncommitted accountability record (MED-8). A non-zero
// value means the audit trail is incomplete and should be investigated.
func WriteFailures() int64 { return writeFailures.Load() }

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

// chainMu serializes the prev-hash read + insert so the hash chain stays
// linear under concurrent writers. All audit writes go through the same DB and
// are not a hot path, so a process-wide mutex is the simplest correct guard:
// without it two goroutines could read the same prev_hash and fork the chain.
var chainMu sync.Mutex

// Log writes entry to the audit_log table and emits a structured slog line. A
// non-nil entry.Err makes the row result='error' with the error message. The
// DB write is the source of truth: if it fails, Log returns that error (callers
// generally ignore it — auditing must never break the mutation it records — but
// it is surfaced for tests and diagnostics) AND emits a LOUD slog.Error so the
// lost accountability record is impossible to miss (MED-8). The slog line is
// always emitted. Each row is hash-chained to its predecessor (MED-9) so any
// later edit/delete is detectable by Verify.
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

	// Hold the chain lock across the prev-hash read and the insert so concurrent
	// writers can't fork the chain on a shared prev_hash.
	chainMu.Lock()
	defer chainMu.Unlock()

	prevHash, err := lastRowHash(ctx, db)
	if err != nil {
		writeFailures.Add(1)
		slog.Error("AUDIT WRITE FAILED — accountability record lost",
			"action", entry.Action, "actor", entry.Actor, "actor_kind", entry.ActorKind,
			"target_type", entry.TargetType, "target_id", entry.TargetID, "error", err.Error())
		return fmt.Errorf("audit: read chain head: %w", err)
	}
	rowHash := computeRowHash(prevHash, rowFields{
		ID: id, At: now, Actor: entry.Actor, ActorKind: entry.ActorKind,
		Action: entry.Action, TargetType: entry.TargetType, TargetID: entry.TargetID,
		SourceIP: entry.SourceIP, Detail: detail, Result: result, Error: errMsg,
	})

	_, err = db.ExecContext(ctx,
		`INSERT INTO audit_log
		 (id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error, prev_hash, row_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, now, entry.Actor, entry.ActorKind, entry.Action,
		entry.TargetType, entry.TargetID, entry.SourceIP, detail, result, errMsg,
		prevHash, rowHash)
	if err != nil {
		writeFailures.Add(1)
		// MED-8: a mutation can commit while its audit row silently fails to write.
		// We do NOT fail the mutation (accountability-vs-availability) but make the
		// loss impossible to miss with a loud, attributed error line.
		slog.Error("AUDIT WRITE FAILED — accountability record lost",
			"action", entry.Action, "actor", entry.Actor, "actor_kind", entry.ActorKind,
			"target_type", entry.TargetType, "target_id", entry.TargetID, "error", err.Error())
		return fmt.Errorf("audit: write log: %w", err)
	}
	return nil
}

// lastRowHash returns the row_hash of the most recent audit row (the chain
// head), or "" when the table is empty (the first row chains from the empty
// string). The newest row is the one with the greatest (at, id) — matching the
// canonical ORDER BY used by Query and Verify.
func lastRowHash(ctx context.Context, db *sql.DB) (string, error) {
	var h string
	err := db.QueryRowContext(ctx,
		`SELECT row_hash FROM audit_log ORDER BY at DESC, id DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return h, nil
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
// port stripped. The controller may run remotely (a droplet) and is reached over
// an SSH-forwarded loopback port or a TLS proxy, but we still do not trust
// X-Forwarded-For — a spoofed header must never forge the recorded source IP, so
// the audit trail keeps the real peer (the proxy/tunnel endpoint) instead.
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
