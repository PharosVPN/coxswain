// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package monitor

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
)

// seedPeer creates a user → device → node → peer chain and returns the peer
// public key plus the resolved device and user ids.
func seedPeer(t *testing.T, conn *sql.DB) (pubKey, deviceID, userID, nodeID string) {
	t.Helper()
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Name: "Alice", Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "phone"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ams-1", Region: "eu"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	const pk = "ABCDEFmockpubkey0123456789012345678901234="
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: node.ID, DeviceID: device.ID, Protocol: "amneziawg", PublicKey: pk, AllowedIP: "10.86.0.5/32",
	}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	return pk, device.ID, user.ID, node.ID
}

func newTestDB(t *testing.T) *sql.DB {
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

// TestSourceIP proves the port is stripped from a source endpoint, for both
// IPv4 and IPv6, and that a bare or empty value is handled.
func TestSourceIP(t *testing.T) {
	cases := map[string]string{
		"198.51.100.23:51820": "198.51.100.23",
		"[2001:db8::1]:443":   "2001:db8::1",
		"":                    "",
	}
	for in, want := range cases {
		if got := SourceIP(in); got != want {
			t.Errorf("SourceIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestResolveKnownPeer proves a known peer public key resolves to its device
// and user via the peers→devices join.
func TestResolveKnownPeer(t *testing.T) {
	conn := newTestDB(t)
	pk, deviceID, userID, _ := seedPeer(t, conn)

	s := NewStore(conn, nil)
	res := s.Resolve(context.Background(), pk)
	if res.DeviceID != deviceID {
		t.Errorf("device_id = %q, want %q", res.DeviceID, deviceID)
	}
	if res.UserID != userID {
		t.Errorf("user_id = %q, want %q", res.UserID, userID)
	}

	// An unknown peer resolves to a zero Resolution (and does not error).
	if got := s.Resolve(context.Background(), "UNKNOWN="); got != (Resolution{}) {
		t.Errorf("unknown peer resolved to %+v, want zero", got)
	}
}

// TestIngestPersistsRow proves an ingested connect event persists a
// connection_events row with the resolved device_id + the source IP (port
// stripped), and that Query returns it.
func TestIngestPersistsRow(t *testing.T) {
	conn := newTestDB(t)
	pk, deviceID, userID, nodeID := seedPeer(t, conn)

	s := NewStore(conn, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	res := s.Resolve(ctx, pk)
	s.Ingest(Event{
		At:             time.Now().UTC(),
		NodeID:         nodeID,
		PeerID:         pk,
		DeviceID:       res.DeviceID,
		UserID:         res.UserID,
		Protocol:       "AMNEZIAWG",
		EventType:      "connect",
		SourceIP:       SourceIP("203.0.113.7:51820"),
		SourceEndpoint: "203.0.113.7:51820",
	})

	rec := waitForOne(t, conn)
	if rec.DeviceID != deviceID || rec.UserID != userID {
		t.Errorf("resolved ids = (%q,%q), want (%q,%q)", rec.DeviceID, rec.UserID, deviceID, userID)
	}
	if rec.SourceIP != "203.0.113.7" {
		t.Errorf("source_ip = %q, want 203.0.113.7 (port stripped)", rec.SourceIP)
	}
	if rec.SourceEndpoint != "203.0.113.7:51820" {
		t.Errorf("source_endpoint = %q", rec.SourceEndpoint)
	}
	if rec.EventType != "connect" {
		t.Errorf("event_type = %q, want connect", rec.EventType)
	}
}

// TestQueryFilters proves the device + source_ip filters narrow the result.
func TestQueryFilters(t *testing.T) {
	conn := newTestDB(t)
	pk, deviceID, userID, nodeID := seedPeer(t, conn)
	ctx := context.Background()

	s := NewStore(conn, nil)
	go s.Run(ctx)
	// One row for our device, one for a different (unresolved) source.
	s.Ingest(Event{At: time.Now().UTC(), NodeID: nodeID, PeerID: pk, DeviceID: deviceID, UserID: userID,
		EventType: "connect", SourceIP: "203.0.113.7", SourceEndpoint: "203.0.113.7:1"})
	s.Ingest(Event{At: time.Now().UTC(), NodeID: nodeID, PeerID: "OTHER=", EventType: "connect",
		SourceIP: "198.51.100.9", SourceEndpoint: "198.51.100.9:2"})

	waitForCount(t, conn, 2)

	byDevice, err := Query(ctx, conn, Filter{DeviceID: deviceID})
	if err != nil {
		t.Fatalf("Query device: %v", err)
	}
	if len(byDevice) != 1 || byDevice[0].DeviceID != deviceID {
		t.Errorf("device filter = %+v, want one row for %s", byDevice, deviceID)
	}

	bySrc, err := Query(ctx, conn, Filter{SourceIP: "198.51.100.9"})
	if err != nil {
		t.Fatalf("Query source_ip: %v", err)
	}
	if len(bySrc) != 1 || bySrc[0].SourceIP != "198.51.100.9" {
		t.Errorf("source_ip filter = %+v, want one row", bySrc)
	}
}

// TestPurge removes rows older than the retention window, keeping fresh ones.
func TestPurge(t *testing.T) {
	conn := newTestDB(t)
	pk, deviceID, userID, nodeID := seedPeer(t, conn)
	ctx := context.Background()

	s := NewStore(conn, nil)
	go s.Run(ctx)
	// One old row (10 days ago) and one fresh row.
	s.Ingest(Event{At: time.Now().UTC().AddDate(0, 0, -10), NodeID: nodeID, PeerID: pk,
		DeviceID: deviceID, UserID: userID, EventType: "connect", SourceIP: "203.0.113.7"})
	s.Ingest(Event{At: time.Now().UTC(), NodeID: nodeID, PeerID: pk,
		DeviceID: deviceID, UserID: userID, EventType: "disconnect", SourceIP: "203.0.113.7"})
	waitForCount(t, conn, 2)

	n, err := Purge(ctx, conn, 7) // keep last 7 days
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d, want 1", n)
	}
	remaining, _ := Query(ctx, conn, Filter{})
	if len(remaining) != 1 || remaining[0].EventType != "disconnect" {
		t.Errorf("after purge = %+v, want the fresh disconnect row", remaining)
	}
}

// waitForOne blocks until exactly one connection_events row exists (the writer
// is async) and returns it.
func waitForOne(t *testing.T, conn *sql.DB) Record {
	t.Helper()
	recs := waitForCount(t, conn, 1)
	return recs[0]
}

// waitForCount polls Query until at least n rows are persisted, failing on
// timeout.
func waitForCount(t *testing.T, conn *sql.DB, n int) []Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		recs, err := Query(context.Background(), conn, Filter{})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(recs) >= n {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d rows; have %d", n, len(recs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
