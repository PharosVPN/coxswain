// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package db

import (
	"io"
	"io/fs"
	"regexp"
	"strings"
	"time"
)

// The migration SQL is SQLite-flavoured. translatingFS wraps the embedded
// migrations filesystem and rewrites each .sql file's contents on read into
// dialect-neutral / Postgres-valid SQL, so the SAME ~33 migrations apply cleanly
// on both backends. SQLite reads the files unmodified (Migrate only wraps the FS
// for the Postgres dialect), so the default path is byte-for-byte unchanged.
//
// This translation pass is preferred over forking every file: the schema is
// almost entirely portable (TEXT, INTEGER, TIMESTAMP, REAL, CHECK, REFERENCES,
// partial unique indexes all work as-is on PG). Only a handful of SQLite-isms
// need rewriting, enumerated in translateMigration.
type translatingFS struct {
	inner fs.FS
}

func (t translatingFS) Open(name string) (fs.File, error) {
	f, err := t.inner.Open(name)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(name, ".sql") {
		return f, nil
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	translated := translateMigrationFile(name, string(data))
	info, _ := fs.Stat(t.inner, name)
	return &memFile{name: name, data: []byte(translated), info: info}, nil
}

func (t translatingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(t.inner, name)
}

// Translation rules. Each is a SQLite-ism that must become Postgres-valid.

var (
	// BLOB → BYTEA. Word-bounded so it never touches a column name containing
	// "blob". The migrations only use BLOB as a bare column type.
	reBlob = regexp.MustCompile(`(?i)\bBLOB\b`)

	// INTEGER PRIMARY KEY AUTOINCREMENT → BIGSERIAL PRIMARY KEY (the legacy
	// audit_log stub at 00001 and the placeholder restored in 00028's Down). PG
	// has no AUTOINCREMENT keyword; BIGSERIAL gives the same auto-assigned id.
	reIntPKAutoinc = regexp.MustCompile(`(?i)\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b`)

	// Any stray AUTOINCREMENT (none remain after the rule above, but keep it
	// defensive so a future migration can't silently break PG).
	reAutoinc = regexp.MustCompile(`(?i)\s*\bAUTOINCREMENT\b`)

	// PRAGMA statements (foreign_keys on/off, foreign_key_check) are SQLite-only.
	// On Postgres they have no equivalent at this granularity and the table
	// rebuild in 00025 does not need them (PG can DROP/RENAME with FKs because
	// 00025 drops and recreates `users` and dependents reference it by a
	// deferred/!validated path — see note below). Strip the whole PRAGMA line.
	rePragmaLine = regexp.MustCompile(`(?im)^\s*PRAGMA[^;]*;\s*$`)
)

// pgOverrides maps a migration filename to a hand-written Postgres body that
// REPLACES the SQLite version entirely, for the few migrations whose semantics
// can't be mechanically translated. The override must apply the SAME schema
// change as the SQLite version so the two backends converge on one schema.
//
// 00025 is the only one: the SQLite version rebuilds the `users` table
// (SQLite can't drop a column's NOT NULL/UNIQUE constraint in place) with
// foreign_keys OFF. On Postgres a DROP TABLE users would fail on the dependent
// FKs from admins/devices/profiles — but PG CAN alter the constraints in place,
// which is both simpler and FK-safe. The net effect matches the SQLite rebuild:
// email becomes nullable, `name` (default ”) and `phone` (nullable, unique)
// are added.
var pgOverrides = map[string]string{
	"migrations/00025_user_identity.sql": `-- +goose Up
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN phone TEXT UNIQUE;

-- +goose Down
ALTER TABLE users DROP COLUMN phone;
ALTER TABLE users DROP COLUMN name;
UPDATE users SET email = 'unknown-' || id WHERE email IS NULL OR email = '';
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
`,

	// 00006 declares forwarding/masquerade/isolation as INTEGER (SQLite has no
	// real boolean — these are 0/1 flags the Go layer binds/scans as bool).
	// Postgres is strict: a Go bool won't encode into int4, and an int4 won't
	// scan back into a *bool. Declaring them BOOLEAN lets pgx round-trip Go bool
	// natively. SQLite keeps the INTEGER version (unchanged default path).
	"migrations/00006_node_network_policy.sql": `-- +goose Up
ALTER TABLE nodes ADD COLUMN forwarding BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE nodes ADD COLUMN masquerade BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE nodes ADD COLUMN isolation  BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE nodes DROP COLUMN isolation;
ALTER TABLE nodes DROP COLUMN masquerade;
ALTER TABLE nodes DROP COLUMN forwarding;
`,

	// NOTE on servers.is_self (00020): it is also a 0/1 flag, BUT — unlike the
	// node policy flags — package fleet binds it via boolToInt(int) and scans it
	// back into an int (see scanServer). So it must STAY INTEGER on Postgres for
	// that code to round-trip; INTEGER is portable and `WHERE is_self = 1` is
	// valid PG (integer = 1), so 00020 needs no override. The two booleans are
	// handled differently only because the Go layer treats them differently.
}

// translateMigrationFile returns the Postgres SQL for the named migration file:
// a full hand-written override when one exists, else the mechanically translated
// SQLite SQL.
func translateMigrationFile(name, sql string) string {
	if override, ok := pgOverrides[name]; ok {
		return override
	}
	return translateMigration(sql)
}

// translateMigration rewrites one migration file's SQLite SQL to Postgres SQL.
// It is a no-op-shaped transform for already-portable statements.
func translateMigration(sql string) string {
	// Order matters: collapse "INTEGER PRIMARY KEY AUTOINCREMENT" before the
	// bare-AUTOINCREMENT sweep, so the latter only catches leftovers.
	sql = reIntPKAutoinc.ReplaceAllString(sql, "BIGSERIAL PRIMARY KEY")
	sql = reAutoinc.ReplaceAllString(sql, "")
	sql = reBlob.ReplaceAllString(sql, "BYTEA")
	sql = rePragmaLine.ReplaceAllString(sql, "")
	return sql
}

// memFile is a read-only in-memory fs.File serving the translated migration
// bytes. goose reads the whole file via io.ReadAll, so Read + Stat + Close is
// all it needs.
type memFile struct {
	name   string
	data   []byte
	off    int
	info   fs.FileInfo
	closed bool
}

func (m *memFile) Stat() (fs.FileInfo, error) {
	if m.info != nil {
		return memFileInfo{name: m.name, size: int64(len(m.data)), info: m.info}, nil
	}
	return memFileInfo{name: m.name, size: int64(len(m.data))}, nil
}

func (m *memFile) Read(p []byte) (int, error) {
	if m.off >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.off:])
	m.off += n
	return n, nil
}

func (m *memFile) Close() error { m.closed = true; return nil }

// memFileInfo reports the translated size while delegating mode/time to the
// underlying entry when available.
type memFileInfo struct {
	name string
	size int64
	info fs.FileInfo
}

func (i memFileInfo) Name() string { return i.name }
func (i memFileInfo) Size() int64  { return i.size }
func (i memFileInfo) Mode() fs.FileMode {
	if i.info != nil {
		return i.info.Mode()
	}
	return 0o444
}
func (i memFileInfo) ModTime() time.Time {
	if i.info != nil {
		return i.info.ModTime()
	}
	return time.Time{}
}
func (i memFileInfo) IsDir() bool      { return false }
func (i memFileInfo) Sys() interface{} { return nil }
