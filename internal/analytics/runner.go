// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// BackendSQLite / BackendPostgres mirror config's backend identifiers, kept
// local so the analytics package does not import config (avoiding an import
// cycle: config has no analytics dependency, and the cli layer wires the two).
const (
	BackendSQLite   = "sqlite"
	BackendPostgres = "postgres"
)

// Engine runs the analytics sweep on a ticker and fans new alerts out via a
// publish callback. It owns the one-time backend-suitability warning.
type Engine struct {
	db       *sql.DB
	geo      GeoResolver
	interval time.Duration
	window   time.Duration
	backend  string
	publish  func(Alert) // called for each NEW/escalated alert; may be nil
	log      *slog.Logger
	warned   bool // backend warning emitted once
}

// Options configures a new Engine. Zero Interval/Window fall back to the package
// defaults. Publish (optional) receives each newly-created alert for live
// fan-out. Backend is the state-store kind ("sqlite"|"postgres") driving the
// one-time suitability warning.
type Options struct {
	GeoIP    GeoResolver
	Interval time.Duration
	Window   time.Duration
	Backend  string
	Publish  func(Alert)
	Logger   *slog.Logger
}

// NewEngine builds an Engine. Call Run with the serve context to start it.
func NewEngine(db *sql.DB, opts Options) *Engine {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	geo := opts.GeoIP
	if geo == nil {
		geo = noGeo{}
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	window := opts.Window
	if window <= 0 {
		window = DefaultWindow
	}
	return &Engine{
		db: db, geo: geo, interval: interval, window: window,
		backend: opts.Backend, publish: opts.Publish, log: log,
	}
}

// Run sweeps once immediately, then every interval until ctx is cancelled. It
// emits the one-time backend warning on the first sweep. Sweep failures are
// logged and retried on the next tick — analytics must never crash the server.
func (e *Engine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	e.warnBackendOnce()
	e.sweepOnce(ctx)

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sweepOnce(ctx)
		}
	}
}

// sweepOnce runs one Sweep and publishes the fresh alerts.
func (e *Engine) sweepOnce(ctx context.Context) {
	fresh, err := Sweep(ctx, e.db, e.geo, time.Now().UTC(), e.window)
	if err != nil {
		e.log.Warn("analytics: sweep failed (will retry)", "err", err)
		return
	}
	for _, a := range fresh {
		e.log.Info("analytics: alert", "kind", a.Kind, "severity", a.Severity,
			"device", a.DeviceID, "id", a.ID)
		if e.publish != nil {
			e.publish(a)
		}
	}
}

// warnBackendOnce emits a single startup WARNING when analytics runs on SQLite,
// pointing the operator at Postgres for production scale. It is silent on
// Postgres and fires at most once per Engine.
func (e *Engine) warnBackendOnce() {
	if e.warned {
		return
	}
	e.warned = true
	if BackendIsSQLite(e.backend) {
		e.log.Warn("analytics is enabled on the SQLite backend — for production/enterprise " +
			"scale (heavy analytical queries + write concurrency) switch the controller to Postgres")
	}
}

// BackendIsSQLite reports whether the named backend is SQLite (the default when
// unrecognised/empty), the case the analytics warning targets.
func BackendIsSQLite(backend string) bool {
	return backend != BackendPostgres
}

// BackendWarning returns the human-readable backend-suitability warning for the
// given backend, or "" when none applies (Postgres). It is the same message
// surfaced on the API status envelope, so the warning is discoverable beyond
// the startup log.
func BackendWarning(backend string) string {
	if BackendIsSQLite(backend) {
		return "analytics is running on SQLite — for production/enterprise scale, " +
			"switch the controller to Postgres (heavy analytical queries + write concurrency)"
	}
	return ""
}
