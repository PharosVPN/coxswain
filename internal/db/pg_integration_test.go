// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

//go:build pg

// Package db's Postgres integration test. It runs ONLY against a real Postgres,
// gated two ways so the default `go test ./...` stays SQLite-only and offline:
//
//   - the `pg` build tag (so the file isn't even compiled by default), and
//   - the COX_TEST_PG_DSN environment variable (the connection string).
//
// Run it against the provided live PG with:
//
//	COX_TEST_PG_DSN='postgres://postgres:postgres@localhost:5432/coxtest' \
//	    go test -tags pg ./internal/db/ -run TestPostgres -v
//
// It exercises the cross-backend surface end-to-end on the real database:
// all migrations apply, a token round-trips through Create/Authenticate, the
// audit hash chain Verifies (the µs-precision regression test), connection
// events ingest and read back via the sessions query, an alert inserts under
// the partial-unique-index and reads back, and core user/device/profile/node
// CRUD round-trips (including BYTEA blobs).
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/idgen"
	"github.com/PharosVPN/coxswain/internal/profile"
)

// openTestPG opens the live Postgres named by COX_TEST_PG_DSN and resets the
// `public` schema so each run starts from an empty database. It returns a
// migrated *sql.DB. The test is skipped when the env var is unset.
func openTestPG(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("COX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("COX_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	if !IsPostgresDSN(dsn) {
		t.Fatalf("COX_TEST_PG_DSN is not a postgres:// DSN: %q", dsn)
	}

	conn, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open(postgres): %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if !IsPostgresBackendConn(conn) {
		t.Fatal("Open did not select the Postgres backend for a postgres:// DSN")
	}

	// Reset to a clean schema so re-runs are deterministic and never collide on
	// the goose version table or unique constraints.
	if _, err := conn.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return conn
}

func TestPostgresMigrateAndCRUD(t *testing.T) {
	conn := openTestPG(t)
	ctx := context.Background()

	// 1. ALL migrations apply on Postgres (the dialect-translation pass).
	if err := Migrate(conn); err != nil {
		t.Fatalf("Migrate(postgres): %v", err)
	}
	// Idempotent.
	if err := Migrate(conn); err != nil {
		t.Fatalf("second Migrate(postgres): %v", err)
	}

	// Confirm the schema landed: spot-check a representative set of tables.
	for _, table := range []string{
		"ca", "users", "devices", "profiles", "nodes", "audit_log",
		"api_tokens", "connection_events", "alerts",
	} {
		var n int
		if err := conn.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.tables
			 WHERE table_schema='public' AND table_name=$1`, table).Scan(&n); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if n != 1 {
			t.Fatalf("expected table %s to exist", table)
		}
	}

	// Confirm BLOB→BYTEA translation: profiles.ciphertext must be bytea on PG.
	var ctype string
	if err := conn.QueryRowContext(ctx,
		`SELECT data_type FROM information_schema.columns
		 WHERE table_name='profiles' AND column_name='ciphertext'`).Scan(&ctype); err != nil {
		t.Fatalf("ciphertext type: %v", err)
	}
	if ctype != "bytea" {
		t.Fatalf("profiles.ciphertext is %q, want bytea (BLOB→BYTEA translation failed)", ctype)
	}

	t.Run("token", func(t *testing.T) { testPGToken(t, ctx, conn) })
	t.Run("audit_chain", func(t *testing.T) { testPGAuditChain(t, ctx, conn) })
	t.Run("connection_events", func(t *testing.T) { testPGConnectionEvents(t, ctx, conn) })
	t.Run("alerts", func(t *testing.T) { testPGAlerts(t, ctx, conn) })
	t.Run("crud", func(t *testing.T) { testPGCRUD(t, ctx, conn) })
}

// testPGToken creates and authenticates an API token (hash + scope round-trip).
func testPGToken(t *testing.T, ctx context.Context, conn *sql.DB) {
	secret, rec, err := authn.Create(ctx, conn, "pg-test", authn.ScopeAdmin, time.Hour, "tester")
	if err != nil {
		t.Fatalf("token Create: %v", err)
	}
	got, err := authn.Authenticate(ctx, conn, secret)
	if err != nil {
		t.Fatalf("token Authenticate: %v", err)
	}
	if got.ID != rec.ID {
		t.Fatalf("authenticated token id = %q, want %q", got.ID, rec.ID)
	}
	if !got.Allows(authn.ScopeMonitor) {
		t.Fatalf("admin-scope token should allow monitor scope")
	}
	// A bogus secret must not authenticate.
	if _, err := authn.Authenticate(ctx, conn, "cox_not-a-real-secret"); err == nil {
		t.Fatal("Authenticate accepted a bogus secret")
	}
}

// testPGAuditChain writes several audit rows and Verifies the hash chain. This
// is THE regression test for the µs-precision bug: Postgres stores `at` at
// microsecond precision, so a nanosecond canonicalisation would break Verify.
func testPGAuditChain(t *testing.T, ctx context.Context, conn *sql.DB) {
	for i := 0; i < 6; i++ {
		err := audit.Log(ctx, conn, audit.Entry{
			Actor: "tester", ActorKind: audit.KindCLI,
			Action: fmt.Sprintf("pg.test.%d", i), TargetType: "node",
			TargetID: idgen.New("nd"), SourceIP: "127.0.0.1",
			Detail: map[string]any{"i": i},
		})
		if err != nil {
			t.Fatalf("audit.Log[%d]: %v", i, err)
		}
	}

	res, err := audit.Verify(ctx, conn)
	if err != nil {
		t.Fatalf("audit.Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain broke on Postgres: brokenID=%s reason=%s (µs-precision regression?)",
			res.BrokenID, res.Reason)
	}
	if res.Checked < 6 {
		t.Fatalf("audit.Verify checked %d rows, want >= 6", res.Checked)
	}

	// Tamper with a row and confirm Verify catches it (the chain is live, not a
	// no-op): editing actor must break the recomputed row_hash.
	if _, err := conn.ExecContext(ctx,
		`UPDATE audit_log SET actor='attacker' WHERE action='pg.test.3'`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	res, err = audit.Verify(ctx, conn)
	if err != nil {
		t.Fatalf("audit.Verify after tamper: %v", err)
	}
	if res.OK {
		t.Fatal("audit.Verify did not detect a tampered row on Postgres")
	}
	// Restore so later sub-tests run against a clean chain (none depend on it,
	// but keep the table consistent).
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM audit_log WHERE action LIKE 'pg.test.%'`); err != nil {
		t.Fatalf("cleanup audit rows: %v", err)
	}
}

// testPGConnectionEvents ingests connection_events (the monitor write shape) and
// reads them back via the sessions query.
func testPGConnectionEvents(t *testing.T, ctx context.Context, conn *sql.DB) {
	deviceID := idgen.New("dev")
	now := time.Now().UTC()
	for i, ev := range []struct {
		kind, ip string
	}{
		{"connect", "203.0.113.7"},
		{"disconnect", "203.0.113.7"},
	} {
		_, err := conn.ExecContext(ctx, `
			INSERT INTO connection_events
			(id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes, reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			idgen.New("cev"), now.Add(time.Duration(i)*time.Second), "node-1", "peerkey",
			deviceID, nil, "amneziawg", ev.kind, ev.ip, ev.ip+":51820", uint64(100), uint64(200), "")
		if err != nil {
			t.Fatalf("insert connection_event[%d]: %v", i, err)
		}
	}

	recs, err := monitorQuery(ctx, conn, deviceID)
	if err != nil {
		t.Fatalf("sessions query: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("sessions query returned %d rows, want 2", len(recs))
	}
	// Newest-first ordering: the disconnect (later `at`) comes first.
	if recs[0].EventType != "disconnect" {
		t.Fatalf("newest event = %q, want disconnect", recs[0].EventType)
	}
	if recs[0].RxBytes != 100 || recs[0].TxBytes != 200 {
		t.Fatalf("byte counters round-trip wrong: rx=%d tx=%d", recs[0].RxBytes, recs[0].TxBytes)
	}
}

// testPGAlerts inserts an alert (JSON columns + the partial unique index on
// status='open') and reads it back through the analytics query.
func testPGAlerts(t *testing.T, ctx context.Context, conn *sql.DB) {
	deviceID := idgen.New("dev")
	now := time.Now().UTC()
	id := idgen.New("alr")
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO alerts
		(id, at, kind, severity, device_id, user_id, node_id, source_ips, detail, status, dedup_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		id, now, "leaked_profile", "warning", deviceID, nil, nil,
		`["203.0.113.7","203.0.113.8"]`, `{"sessions":2}`, "open", "dedup-pg-1", now, now); err != nil {
		t.Fatalf("insert alert: %v", err)
	}

	// The partial unique index must reject a SECOND open alert with the same
	// dedup_key (idx_alerts_dedup_open ... WHERE status='open').
	_, err := conn.ExecContext(ctx, `
		INSERT INTO alerts
		(id, at, kind, severity, device_id, source_ips, detail, status, dedup_key, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		idgen.New("alr"), now, "leaked_profile", "warning", deviceID,
		`[]`, `{}`, "open", "dedup-pg-1", now, now)
	if err == nil {
		t.Fatal("partial unique index did not reject a duplicate open alert")
	}

	alerts, err := analytics.Query(ctx, conn, analytics.Filter{Status: "open"})
	if err != nil {
		t.Fatalf("analytics.Query: %v", err)
	}
	var found *analytics.Alert
	for i := range alerts {
		if alerts[i].ID == id {
			found = &alerts[i]
			break
		}
	}
	if found == nil {
		t.Fatal("inserted alert not returned by analytics.Query")
	}
	if len(found.SourceIPs) != 2 {
		t.Fatalf("source_ips JSON round-trip: got %v", found.SourceIPs)
	}
}

// testPGCRUD round-trips core user/device/profile/node records, including a
// BYTEA blob (the sealed profile bundle and the user encryption key).
func testPGCRUD(t *testing.T, ctx context.Context, conn *sql.DB) {
	u, err := account.CreateUser(ctx, conn, account.User{
		Name: "Ada", Email: fmt.Sprintf("ada+%s@example.com", idgen.New("e")), Role: "user", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	dev, err := account.CreateDevice(ctx, conn, account.Device{
		UserID: u.ID, Name: "laptop", Platform: "macos", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// BYTEA round-trip: store an encryption key, then seal+store a profile.
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	if err := account.SetEncryptionKey(ctx, conn, u.ID, pub, []byte("wrapped-priv")); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	gotPub, gotWrapped, err := account.GetEncryptionKey(ctx, conn, u.ID)
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	if string(gotPub) != string(pub) || string(gotWrapped) != "wrapped-priv" {
		t.Fatalf("BYTEA round-trip mismatch: pub=%v wrapped=%q", gotPub, gotWrapped)
	}

	rev, err := profile.Issue(ctx, conn, u.ID, dev.ID, profile.Profile{FleetID: "fleet-pg-test"})
	if err != nil {
		t.Fatalf("profile.Issue: %v", err)
	}
	if rev != 1 {
		t.Fatalf("first profile revision = %d, want 1", rev)
	}
	cipher, gotRev, err := profile.LatestCiphertext(ctx, conn, u.ID, dev.ID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	if gotRev != 1 || len(cipher) == 0 {
		t.Fatalf("profile bundle round-trip failed: rev=%d len=%d", gotRev, len(cipher))
	}

	// Fleet node CRUD.
	n, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "ny-1", Region: "nyc", PublicIP: "198.51.100.10", Status: "pending",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	got, err := fleet.GetNode(ctx, conn, n.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Name != "ny-1" || got.Region != "nyc" {
		t.Fatalf("node round-trip mismatch: %+v", got)
	}
}

// monitorQuery wraps the sessions query for the named device, mirroring the
// /api/sessions read path without importing the monitor package's Filter shape
// inline at every call site.
func monitorQuery(ctx context.Context, conn *sql.DB, deviceID string) ([]monitorRecord, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT id, at, node_id, peer_id, device_id, user_id, protocol, event_type,
		       source_ip, source_endpoint, rx_bytes, tx_bytes, reason
		FROM connection_events WHERE device_id = ? ORDER BY at DESC, id DESC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []monitorRecord
	for rows.Next() {
		var (
			r              monitorRecord
			nodeID, peerID sql.NullString
			devID, userID  sql.NullString
			proto, srcIP   sql.NullString
			srcEnd, reason sql.NullString
			at             time.Time
		)
		if err := rows.Scan(&r.ID, &at, &nodeID, &peerID, &devID, &userID,
			&proto, &r.EventType, &srcIP, &srcEnd, &r.RxBytes, &r.TxBytes, &reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type monitorRecord struct {
	ID        string
	EventType string
	RxBytes   uint64
	TxBytes   uint64
}
