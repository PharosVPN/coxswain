// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package db

import "testing"

// TestRebindPositional checks the `?`→`$N` rewrite, including the literal-aware
// cases (a `?` inside a string/identifier/comment must NOT be rebound). This is
// the correctness guard for the driver-level rebind that lets the `?`-everywhere
// data layer run unchanged on Postgres.
func TestRebindPositional(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"none", `SELECT 1`, `SELECT 1`},
		{"single", `SELECT * FROM t WHERE id = ?`, `SELECT * FROM t WHERE id = $1`},
		{
			"multi",
			`INSERT INTO t (a,b,c) VALUES (?, ?, ?)`,
			`INSERT INTO t (a,b,c) VALUES ($1, $2, $3)`,
		},
		{
			"many",
			`VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			`VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		},
		{
			"question_in_single_quote_literal",
			`SELECT * FROM t WHERE name = 'a?b' AND id = ?`,
			`SELECT * FROM t WHERE name = 'a?b' AND id = $1`,
		},
		{
			"escaped_quote_in_literal",
			`SELECT '?''?' , ? FROM t`,
			`SELECT '?''?' , $1 FROM t`,
		},
		{
			"question_in_double_quoted_identifier",
			`SELECT "we?rd" FROM t WHERE x = ?`,
			`SELECT "we?rd" FROM t WHERE x = $1`,
		},
		{
			"question_in_line_comment",
			"SELECT ? -- is this ok?\nFROM t",
			"SELECT $1 -- is this ok?\nFROM t",
		},
		{
			"question_in_block_comment",
			`SELECT /* a ? b */ ? FROM t`,
			`SELECT /* a ? b */ $1 FROM t`,
		},
		{
			"dollar_quote_passthrough",
			`SELECT $tag$ a ? b $tag$, ? FROM t`,
			`SELECT $tag$ a ? b $tag$, $1 FROM t`,
		},
		{
			"existing_pg_param_untouched",
			`SELECT * FROM t WHERE id = $1`,
			`SELECT * FROM t WHERE id = $1`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rebindPositional(c.in); got != c.want {
				t.Fatalf("rebindPositional(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}

// TestIsPostgresDSN checks the backend selector.
func TestIsPostgresDSN(t *testing.T) {
	for _, c := range []struct {
		dsn string
		pg  bool
	}{
		{"postgres://u:p@h:5432/db", true},
		{"postgresql://u@h/db", true},
		{"POSTGRES://u@h/db", true},
		{"/var/lib/cox/app.db", false},
		{"app.db", false},
		{"", false},
		{"file:app.db?_pragma=foreign_keys(1)", false},
	} {
		if got := IsPostgresDSN(c.dsn); got != c.pg {
			t.Errorf("IsPostgresDSN(%q) = %v, want %v", c.dsn, got, c.pg)
		}
	}
}

// TestTranslateMigration spot-checks the SQLite→Postgres dialect translation.
func TestTranslateMigration(t *testing.T) {
	in := `CREATE TABLE t (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    blob_col BLOB NOT NULL
);
PRAGMA foreign_keys=OFF;
`
	got := translateMigration(in)
	if want := "BIGSERIAL PRIMARY KEY"; !contains(got, want) {
		t.Errorf("AUTOINCREMENT not translated:\n%s", got)
	}
	if !contains(got, "BYTEA") || contains(got, "BLOB") {
		t.Errorf("BLOB not translated to BYTEA:\n%s", got)
	}
	if contains(got, "PRAGMA") || contains(got, "AUTOINCREMENT") {
		t.Errorf("PRAGMA/AUTOINCREMENT not stripped:\n%s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
