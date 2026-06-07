// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package db

import (
	"context"
	"database/sql"
	"database/sql/driver"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// The data layer is written with `?` placeholders (the SQLite/MySQL convention).
// Postgres expects `$1, $2, ...`. Rather than touch ~150 call sites across a
// dozen packages, we wrap pgx's database/sql driver so every query is rebound
// to `$N` form at the chokepoint the standard library funnels all Exec/Query/
// Prepare calls through: a Conn's PrepareContext / ExecContext / QueryContext.
//
// pgx's *stdlib.Conn already implements driver.QueryerContext, driver.ExecerContext
// and driver.ConnPrepareContext, so database/sql never falls back to the legacy
// non-context paths — wrapping only those three methods covers every query. The
// rebind is literal-aware (rebindPositional), so a `?` inside a string is left
// alone.

// pgxRebindDriverName is the database/sql driver registered for Postgres DSNs.
const pgxRebindDriverName = "pgx-rebind"

func init() {
	// Register a placeholder Driver under our name so database/sql recognises it.
	// We never actually open through this registered Driver (which has no DSN
	// config); openPostgres builds a Connector directly. Registering keeps the
	// name valid and lets sql.Drivers() report it.
	sql.Register(pgxRebindDriverName, &rebindDriver{})
}

// openPostgres opens a *sql.DB backed by pgx with automatic `?`→`$N` rebinding.
// dsn is a libpq/pgx connection string (e.g. postgres://user:pass@host/db).
func openPostgres(dsn string) (*sql.DB, error) {
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	base := stdlib.GetConnector(*connConfig)
	return sql.OpenDB(&rebindConnector{base: base}), nil
}

// rebindDriver is a stub Driver registered under pgxRebindDriverName. Opening
// through it directly is unsupported (we always go via openPostgres's Connector),
// so Open errors clearly if ever called.
type rebindDriver struct{}

func (rebindDriver) Open(string) (driver.Conn, error) {
	return nil, driver.ErrBadConn
}

// rebindConnector wraps pgx's stdlib connector, returning rebindConn connections
// that rewrite `?` placeholders to `$N` before handing the query to pgx.
type rebindConnector struct {
	base driver.Connector
}

func (c *rebindConnector) Connect(ctx context.Context) (driver.Conn, error) {
	inner, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &rebindConn{inner: inner}, nil
}

func (c *rebindConnector) Driver() driver.Driver { return &rebindDriver{} }

// rebindConn wraps a pgx *stdlib.Conn. It rebinds the query in the three
// context-aware methods database/sql prefers; pgx implements all three, so the
// non-context fallbacks are never reached for our usage. CheckNamedValue and
// other optional interfaces are forwarded to keep pgx's type handling intact.
type rebindConn struct {
	inner driver.Conn
}

// Compile-time assertions that we implement the interfaces database/sql checks
// for, so it never falls back to a path that skips rebinding.
var (
	_ driver.Conn               = (*rebindConn)(nil)
	_ driver.ConnPrepareContext = (*rebindConn)(nil)
	_ driver.ExecerContext      = (*rebindConn)(nil)
	_ driver.QueryerContext     = (*rebindConn)(nil)
	_ driver.ConnBeginTx        = (*rebindConn)(nil)
	_ driver.NamedValueChecker  = (*rebindConn)(nil)
	_ driver.SessionResetter    = (*rebindConn)(nil)
	_ driver.Validator          = (*rebindConn)(nil)
)

func (c *rebindConn) Prepare(query string) (driver.Stmt, error) {
	return c.inner.Prepare(rebindPositional(query))
}

func (c *rebindConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.inner.(driver.ConnPrepareContext).PrepareContext(ctx, rebindPositional(query))
}

func (c *rebindConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.inner.(driver.ExecerContext).ExecContext(ctx, rebindPositional(query), args)
}

func (c *rebindConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.inner.(driver.QueryerContext).QueryContext(ctx, rebindPositional(query), args)
}

func (c *rebindConn) Begin() (driver.Tx, error) { return c.inner.Begin() } //nolint:staticcheck // forwarding

func (c *rebindConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.inner.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *rebindConn) Close() error { return c.inner.Close() }

func (c *rebindConn) CheckNamedValue(nv *driver.NamedValue) error {
	if checker, ok := c.inner.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func (c *rebindConn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *rebindConn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}
