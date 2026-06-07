// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package audit

// The audit log is hash-chained for tamper-evidence (MED-9): each row carries
// the row_hash of its predecessor (prev_hash) and its own row_hash, computed as
//
//	row_hash = sha256hex( prev_hash || canonical(row fields) )
//
// where canonical() is a deterministic, length-prefixed encoding of every stored
// field. Editing or deleting any row breaks the link to the next row, so Verify
// (walking the chain oldest→newest) reports the first break. This backs the
// "append-only" claim with detectable evidence — a single static-binary,
// no-extra-infrastructure integrity check, not a cryptographic anchor (an admin
// with DB write access could still recompute the whole tail; the value is making
// silent in-place edits/deletes observable).

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// auditTimePrecision is the precision the audit timestamp is truncated to before
// it is both STORED and CANONICALIZED. It must be the coarsest precision any
// supported backend persists, so a written-then-read-back timestamp is identical
// on every backend and the hash chain round-trips. PostgreSQL's `timestamp` is
// MICROSECOND precision (it silently drops sub-µs digits), so a nanosecond value
// hashed at write time would never match the recomputed hash after a round-trip.
// Truncating to microseconds on BOTH sides makes the chain verify on Postgres
// AND SQLite (SQLite stores the full value, but truncated input round-trips
// unchanged). Storing with this precision is the single source of truth — see
// audit.StoreTime and canonical().
const auditTimePrecision = time.Microsecond

// StoreTime normalises a timestamp to the precision actually persisted across
// backends (microseconds) and to UTC. Both the value written to audit_log.at and
// the value fed into the hash MUST pass through here, so write-time and
// read-back canonicalisations agree byte-for-byte regardless of backend.
func StoreTime(t time.Time) time.Time {
	return t.UTC().Truncate(auditTimePrecision)
}

// rowFields is the exact set of stored columns that participate in a row's hash,
// in a fixed order. at is encoded as UnixNano (truncated to microseconds, the
// cross-backend-stable precision) so it is independent of the DB's timestamp
// text rendering AND of Postgres's microsecond storage precision.
type rowFields struct {
	ID         string
	At         time.Time
	Actor      string
	ActorKind  string
	Action     string
	TargetType string
	TargetID   string
	SourceIP   string
	Detail     string
	Result     string
	Error      string
}

// canonical serializes the row fields deterministically: each string field is
// length-prefixed (8-byte big-endian length, then the bytes) so no concatenation
// of distinct field values can collide with another, and the timestamp is its
// UnixNano as 8 big-endian bytes. Field order is fixed by this function.
func (f rowFields) canonical() []byte {
	var buf []byte
	putStr := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		buf = append(buf, n[:]...)
		buf = append(buf, s...)
	}
	putInt := func(v int64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v))
		buf = append(buf, n[:]...)
	}
	putStr(f.ID)
	// Truncate to the cross-backend-stable precision before hashing, so the
	// canonical form is identical whether At came straight from time.Now (SQLite
	// keeps full nanos) or was read back from a Postgres microsecond column.
	putInt(StoreTime(f.At).UnixNano())
	putStr(f.Actor)
	putStr(f.ActorKind)
	putStr(f.Action)
	putStr(f.TargetType)
	putStr(f.TargetID)
	putStr(f.SourceIP)
	putStr(f.Detail)
	putStr(f.Result)
	putStr(f.Error)
	return buf
}

// computeRowHash returns the hex-encoded sha256 of (prevHash || canonical(f)).
func computeRowHash(prevHash string, f rowFields) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(f.canonical())
	return hex.EncodeToString(h.Sum(nil))
}

// Backfill computes prev_hash/row_hash for any rows that lack a row_hash,
// oldest→newest, so a database that already held audit rows when the hash-chain
// migration applied verifies cleanly. It is idempotent: rows with a non-empty
// row_hash are left untouched, and it chains new work onto the last already-
// hashed row, so it is safe to run on every start. db.Migrate calls it right
// after the migration that adds the columns.
func Backfill(ctx context.Context, db *sql.DB) error {
	chainMu.Lock()
	defer chainMu.Unlock()

	// Seed prevHash from the newest already-hashed row (if any), so a partially
	// backfilled table continues the existing chain rather than restarting it.
	prevHash := ""
	err := db.QueryRowContext(ctx,
		`SELECT row_hash FROM audit_log WHERE row_hash <> '' ORDER BY at DESC, id DESC LIMIT 1`).
		Scan(&prevHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("audit: backfill seed: %w", err)
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, at, actor, actor_kind, action, target_type, target_id,
		        source_ip, detail, result, error
		 FROM audit_log WHERE row_hash = '' ORDER BY at ASC, id ASC`)
	if err != nil {
		return fmt.Errorf("audit: backfill query: %w", err)
	}
	defer rows.Close()

	type update struct {
		id, prev, hash string
	}
	var updates []update
	for rows.Next() {
		var f rowFields
		if err := rows.Scan(&f.ID, &f.At, &f.Actor, &f.ActorKind, &f.Action,
			&f.TargetType, &f.TargetID, &f.SourceIP, &f.Detail, &f.Result, &f.Error); err != nil {
			return err
		}
		hash := computeRowHash(prevHash, f)
		updates = append(updates, update{id: f.ID, prev: prevHash, hash: hash})
		prevHash = hash
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, u := range updates {
		if _, err := db.ExecContext(ctx,
			`UPDATE audit_log SET prev_hash = ?, row_hash = ? WHERE id = ?`,
			u.prev, u.hash, u.id); err != nil {
			return fmt.Errorf("audit: backfill update %s: %w", u.id, err)
		}
	}
	return nil
}

// VerifyResult reports the outcome of a chain walk. OK is true when every row's
// stored row_hash matches a freshly recomputed hash AND each prev_hash equals
// the prior row's row_hash. On the first break, OK is false and BrokenID /
// Reason identify it; Checked counts rows walked up to and including the break.
type VerifyResult struct {
	OK       bool
	Checked  int
	BrokenID string // id of the first row that fails (empty when OK)
	Reason   string // human-readable description of the break (empty when OK)
}

// Verify walks the audit chain oldest→newest and reports the first tamper break.
// An empty table verifies OK. It detects an edited row (recomputed row_hash
// differs from the stored one), a broken link (prev_hash doesn't match the prior
// row's row_hash — the signature of a deleted/reordered row), and a tampered
// head. It reads with the same ordering Log writes with, so the recomputation is
// deterministic.
func Verify(ctx context.Context, db *sql.DB) (VerifyResult, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, at, actor, actor_kind, action, target_type, target_id,
		        source_ip, detail, result, error, prev_hash, row_hash
		 FROM audit_log ORDER BY at ASC, id ASC`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	prevHash := "" // the empty string seeds the chain (genesis prev_hash)
	checked := 0
	for rows.Next() {
		var (
			f                  rowFields
			storedPrev, stored string
		)
		if err := rows.Scan(&f.ID, &f.At, &f.Actor, &f.ActorKind, &f.Action,
			&f.TargetType, &f.TargetID, &f.SourceIP, &f.Detail, &f.Result, &f.Error,
			&storedPrev, &stored); err != nil {
			return VerifyResult{}, err
		}
		checked++

		// Link check: this row must chain from the previous row's row_hash. A
		// mismatch is the signature of a deleted or reordered predecessor.
		if storedPrev != prevHash {
			return VerifyResult{
				OK: false, Checked: checked, BrokenID: f.ID,
				Reason: "prev_hash does not match the preceding row's row_hash (deleted/reordered row?)",
			}, nil
		}
		// Content check: recompute the row's hash from its stored fields.
		want := computeRowHash(storedPrev, f)
		if want != stored {
			return VerifyResult{
				OK: false, Checked: checked, BrokenID: f.ID,
				Reason: "row_hash does not match recomputed hash (row was edited)",
			}, nil
		}
		prevHash = stored
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{OK: true, Checked: checked}, nil
}
