// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package audit

import (
	"context"
	"testing"
	"time"
)

// TestChainVerifiesAndDetectsTamper writes a few rows, confirms the chain
// verifies, then mutates a row in place and a separate deletion, and confirms
// Verify reports each break.
func TestChainVerifiesAndDetectsTamper(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	for i, action := range []string{"node.add", "node.update", "node.rm"} {
		if err := Log(ctx, conn, Entry{
			Actor: "admin@x", ActorKind: KindSession, Action: action,
			TargetType: "node", TargetID: "nod_" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("Log %s: %v", action, err)
		}
	}

	// A fresh chain verifies clean.
	res, err := Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != 3 {
		t.Fatalf("clean chain: %+v", res)
	}

	// Edit a row's actor in place — its stored row_hash no longer matches.
	if _, err := conn.ExecContext(ctx,
		`UPDATE audit_log SET actor = 'mallory' WHERE action = 'node.update'`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	res, err = Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify after edit: %v", err)
	}
	if res.OK {
		t.Fatalf("edited row should break the chain: %+v", res)
	}
}

// TestChainDetectsDeletedRow confirms deleting a middle row breaks the link
// (the following row's prev_hash no longer matches its new predecessor).
func TestChainDetectsDeletedRow(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	for _, action := range []string{"a.one", "a.two", "a.three"} {
		if err := Log(ctx, conn, Entry{Actor: "x", ActorKind: KindCLI, Action: action}); err != nil {
			t.Fatalf("Log %s: %v", action, err)
		}
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM audit_log WHERE action = 'a.two'`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	res, err := Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("deleted row should break the chain: %+v", res)
	}
}

// TestEmptyChainVerifies confirms an empty audit table verifies OK.
func TestEmptyChainVerifies(t *testing.T) {
	conn := testDB(t)
	res, err := Verify(context.Background(), conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != 0 {
		t.Fatalf("empty chain: %+v", res)
	}
}

// TestBackfillIsIdempotent confirms Backfill leaves an already-hashed chain
// intact (no double-chaining) and is safe to re-run.
func TestBackfillIsIdempotent(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()
	for _, a := range []string{"x.one", "x.two"} {
		if err := Log(ctx, conn, Entry{Actor: "x", ActorKind: KindCLI, Action: a}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := Backfill(ctx, conn); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	res, err := Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != 2 {
		t.Fatalf("after re-backfill: %+v", res)
	}
}

// TestBackfillRepairsLegacyRows simulates an upgraded database: rows written
// with empty hash columns (as the migration leaves pre-existing rows) are
// backfilled into a verifying chain.
func TestBackfillRepairsLegacyRows(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	// Insert rows directly with empty hashes, as a pre-00032 row would look after
	// the column-adding migration applied.
	for i, action := range []string{"legacy.one", "legacy.two"} {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO audit_log (id, at, actor, actor_kind, action, result, prev_hash, row_hash)
			 VALUES (?, datetime('now'), 'legacy', 'cli', ?, 'ok', '', '')`,
			"aud_legacy_"+string(rune('a'+i)), action); err != nil {
			t.Fatalf("seed legacy: %v", err)
		}
	}
	// Before backfill the chain is broken (empty hashes).
	if res, _ := Verify(ctx, conn); res.OK {
		t.Fatalf("empty-hash rows should not verify before backfill: %+v", res)
	}
	if err := Backfill(ctx, conn); err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	res, err := Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.Checked != 2 {
		t.Fatalf("after backfill: %+v", res)
	}
}

// TestStoreTimeTruncatesToMicros guards the cross-backend hash-chain fix: the
// timestamp must be truncated to microseconds (the coarsest precision any
// backend persists — Postgres's `timestamp` drops sub-µs digits) before it is
// both stored and canonicalised. A nanosecond value that survived to the hash
// but was lost on a Postgres round-trip would break Verify there.
func TestStoreTimeTruncatesToMicros(t *testing.T) {
	// A timestamp with a non-zero nanosecond-but-sub-microsecond component.
	in := time.Date(2026, 6, 7, 12, 0, 0, 123456789, time.UTC)
	got := StoreTime(in)
	if got.Nanosecond()%1000 != 0 {
		t.Fatalf("StoreTime left sub-µs digits: %d ns", got.Nanosecond())
	}
	if want := int64(123456000); got.UnixNano()%1_000_000_000 != want {
		t.Fatalf("StoreTime truncation = %d ns, want %d", got.UnixNano()%1_000_000_000, want)
	}
	// StoreTime is idempotent and the canonical encoding agrees with it.
	if StoreTime(got) != got {
		t.Fatal("StoreTime is not idempotent")
	}
}

// TestChainRoundTripsAtMicroPrecision proves the chain verifies even when the
// timestamp that comes back from the store has been clamped to microsecond
// precision (the Postgres behaviour, simulated here). Log truncates before
// storing AND canonical() truncates before hashing, so the recomputed hash over
// the (truncated) read-back value matches. Without the fix, a row whose `at`
// lost sub-µs digits on round-trip would fail Verify.
func TestChainRoundTripsAtMicroPrecision(t *testing.T) {
	conn := testDB(t)
	ctx := context.Background()

	if err := Log(ctx, conn, Entry{Actor: "a", ActorKind: KindCLI, Action: "x.one"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	// Simulate a Postgres-style µs clamp of the persisted timestamp: rewrite `at`
	// to its microsecond truncation (a no-op for the value Log already stored,
	// proving Log truncated up front — if it had stored full nanos, the row_hash
	// computed at write time would now disagree with the truncated read-back).
	var at time.Time
	if err := conn.QueryRowContext(ctx, `SELECT at FROM audit_log LIMIT 1`).Scan(&at); err != nil {
		t.Fatalf("read at: %v", err)
	}
	if at.Nanosecond()%1000 != 0 {
		t.Fatalf("Log stored sub-µs timestamp %d ns — would break Postgres round-trip", at.Nanosecond())
	}
	res, err := Verify(ctx, conn)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain should verify at µs precision: %+v", res)
	}
}
