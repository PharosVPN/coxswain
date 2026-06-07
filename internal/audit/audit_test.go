// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package audit

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return conn
}

// TestLogOK writes a successful mutation and reads it back.
func TestLogOK(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	if err := Log(ctx, conn, Entry{
		Actor: "admin@x", ActorKind: KindSession, Action: "node.add",
		TargetType: "node", TargetID: "nod_1", SourceIP: "127.0.0.1",
		Detail: map[string]any{"region": "eu"},
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	records, err := Query(ctx, conn, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	r := records[0]
	if r.Action != "node.add" || r.Actor != "admin@x" || r.Result != ResultOK {
		t.Errorf("record: %+v", r)
	}
	if r.TargetID != "nod_1" || r.SourceIP != "127.0.0.1" {
		t.Errorf("target/ip: %+v", r)
	}
	if r.Detail["region"] != "eu" {
		t.Errorf("detail: %+v", r.Detail)
	}
	if r.Error != "" {
		t.Errorf("ok row should have no error, got %q", r.Error)
	}
}

// TestLogError writes a failed mutation with result=error and the message.
func TestLogError(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	if err := Log(ctx, conn, Entry{
		Actor: "admin@x", ActorKind: KindSession, Action: "node.rm",
		TargetType: "node", TargetID: "nod_x", Err: errors.New("boom"),
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	records, err := Query(ctx, conn, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records: got %d want 1", len(records))
	}
	if records[0].Result != ResultError || records[0].Error != "boom" {
		t.Errorf("error row: %+v", records[0])
	}
}

// TestQueryFilters checks the actor/action/target filters and the limit cap.
func TestQueryFilters(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	mustLog(t, conn, Entry{Actor: "a", Action: "node.add", TargetID: "n1"})
	mustLog(t, conn, Entry{Actor: "b", Action: "node.rm", TargetID: "n1"})
	mustLog(t, conn, Entry{Actor: "a", Action: "profile.create", TargetID: "p1"})

	byActor, _ := Query(ctx, conn, Filter{Actor: "a"})
	if len(byActor) != 2 {
		t.Errorf("by actor a: got %d want 2", len(byActor))
	}
	byAction, _ := Query(ctx, conn, Filter{Action: "node.rm"})
	if len(byAction) != 1 || byAction[0].Actor != "b" {
		t.Errorf("by action: %+v", byAction)
	}
	byTarget, _ := Query(ctx, conn, Filter{TargetID: "n1"})
	if len(byTarget) != 2 {
		t.Errorf("by target n1: got %d want 2", len(byTarget))
	}

	// Limit cap: a huge limit is clamped to MaxLimit, not rejected.
	all, _ := Query(ctx, conn, Filter{Limit: 99999})
	if len(all) != 3 {
		t.Errorf("limit cap: got %d want 3", len(all))
	}
}

// TestPurge removes only rows older than the retention window.
func TestPurge(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	// Two rows: one recent, one 10 days old.
	mustLog(t, conn, Entry{Actor: "recent", Action: "node.add"})
	old := time.Now().UTC().AddDate(0, 0, -10)
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO audit_log (id, at, actor, actor_kind, action, result)
		 VALUES ('aud_old', ?, 'old', 'cli', 'node.rm', 'ok')`, old); err != nil {
		t.Fatalf("seed old: %v", err)
	}

	// Retain 7 days: the 10-day-old row goes, the recent one stays.
	n, err := Purge(ctx, conn, 7)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged: got %d want 1", n)
	}
	remaining, _ := Query(ctx, conn, Filter{})
	if len(remaining) != 1 || remaining[0].Actor != "recent" {
		t.Errorf("remaining: %+v", remaining)
	}

	// days <= 0 disables retention (no-op).
	if got, _ := Purge(ctx, conn, 0); got != 0 {
		t.Errorf("purge with 0 days: got %d want 0", got)
	}
}

func mustLog(t *testing.T, conn *sql.DB, e Entry) {
	t.Helper()
	if err := Log(context.Background(), conn, e); err != nil {
		t.Fatalf("Log: %v", err)
	}
}
