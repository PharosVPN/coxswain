// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package db opens coxswain's state database and applies Goose migrations. The
// default backend is the embedded pure-Go SQLite engine (modernc.org/sqlite); a
// Postgres DSN (postgres:// or postgresql://) switches it to pgx — also pure-Go,
// so the controller stays a single static binary (CGO_ENABLED=0) either way.
package db

import (
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// IsPostgresDSN reports whether dsn selects the Postgres backend. Anything that
// is not a postgres://-style URL is treated as a SQLite file path (the default,
// historical behaviour).
func IsPostgresDSN(dsn string) bool {
	s := strings.ToLower(strings.TrimSpace(dsn))
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// Open opens (creating if absent) the state database. When dsn is a postgres://
// or postgresql:// URL it opens the pgx-backed Postgres connection (with `?`→`$N`
// placeholder rebinding); otherwise dsn is treated as a SQLite file path and the
// historical SQLite engine is opened with WAL + foreign keys, exactly as before.
func Open(dsn string) (*sql.DB, error) {
	if IsPostgresDSN(dsn) {
		return openPostgresDB(dsn)
	}
	return openSQLite(dsn)
}

// openSQLite opens the pure-Go SQLite database at path. Foreign keys are enforced
// and WAL mode is enabled so reads do not block the control loop.
func openSQLite(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// SQLite serialises writes; a single connection keeps semantics simple and
	// avoids "database is locked" under the controller's concurrent callers.
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping %s: %w", path, err)
	}
	return conn, nil
}

// openPostgresDB opens the pgx-backed Postgres connection and verifies it. Unlike
// SQLite, Postgres handles concurrent writers, so the connection pool is left at
// the database/sql defaults.
func openPostgresDB(dsn string) (*sql.DB, error) {
	conn, err := openPostgres(dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return conn, nil
}

// Migrate applies all pending migrations embedded in the binary, using the
// dialect that matches the backend. For Postgres the SQLite-flavoured migration
// SQL is translated on the fly (BLOB→BYTEA, AUTOINCREMENT, PRAGMA stripping — see
// translateMigration); SQLite uses the SQL verbatim.
func Migrate(conn *sql.DB) error {
	return migrateWith(conn, IsPostgresBackendConn(conn))
}

// MigrateDSN is like Migrate but selects the dialect from the DSN, for callers
// that have the DSN handy and want to be explicit.
func MigrateDSN(conn *sql.DB, dsn string) error {
	return migrateWith(conn, IsPostgresDSN(dsn))
}

func migrateWith(conn *sql.DB, postgres bool) error {
	goose.SetLogger(goose.NopLogger())
	if postgres {
		goose.SetBaseFS(translatingFS{migrationsFS})
		if err := goose.SetDialect("postgres"); err != nil {
			return fmt.Errorf("set goose dialect: %w", err)
		}
	} else {
		goose.SetBaseFS(migrationsFS)
		if err := goose.SetDialect("sqlite3"); err != nil {
			return fmt.Errorf("set goose dialect: %w", err)
		}
	}
	if err := goose.Up(conn, "migrations"); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// IsPostgresBackendConn reports whether conn is the pgx-rebind Postgres backend,
// by inspecting the registered driver. This lets Migrate pick the dialect without
// the DSN being threaded through.
func IsPostgresBackendConn(conn *sql.DB) bool {
	switch conn.Driver().(type) {
	case *rebindDriver:
		return true
	default:
		return false
	}
}
