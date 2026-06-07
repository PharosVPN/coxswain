// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package audit

import (
	"context"
	"testing"
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
