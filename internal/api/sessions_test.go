// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/monitor"
)

// seedSession persists one connection_events row through the monitor store and
// returns the device id it resolved to. The store writer is async; this blocks
// until the row lands.
func seedSession(t *testing.T, conn *sql.DB) (deviceID, sourceIP string) {
	t.Helper()
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Name: "Bob", Email: "bob@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "laptop"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ny-1", Region: "us"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	const pk = "SESSIONpubkey000000000000000000000000000000="
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: node.ID, DeviceID: device.ID, Protocol: "amneziawg", PublicKey: pk, AllowedIP: "10.86.0.9/32",
	}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}

	store := monitor.NewStore(conn, nil)
	go store.Run(ctx)
	res := store.Resolve(ctx, pk)
	store.Ingest(monitor.Event{
		At: time.Now().UTC(), NodeID: node.ID, PeerID: pk,
		DeviceID: res.DeviceID, UserID: res.UserID, Protocol: "AMNEZIAWG",
		EventType: "connect", SourceIP: monitor.SourceIP("203.0.113.40:1194"),
		SourceEndpoint: "203.0.113.40:1194",
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		recs, err := monitor.Query(ctx, conn, monitor.Filter{})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(recs) > 0 {
			return device.ID, "203.0.113.40"
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the session row to persist")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSessionsReturnsFilteredRows: a session admin reads /api/sessions and the
// device + source_ip filters narrow the result to the seeded row, carrying the
// resolved device id and the port-stripped source IP.
func TestSessionsReturnsFilteredRows(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	deviceID, sourceIP := seedSession(t, conn)

	resp, err := client.Get(ts.URL + "/api/sessions?device=" + deviceID)
	if err != nil {
		t.Fatalf("get sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sessions: status %d want 200", resp.StatusCode)
	}
	var recs []monitor.Record
	if err := json.NewDecoder(resp.Body).Decode(&recs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("sessions: got %d rows want 1", len(recs))
	}
	if recs[0].DeviceID != deviceID {
		t.Errorf("device_id = %q, want %q", recs[0].DeviceID, deviceID)
	}
	if recs[0].SourceIP != sourceIP {
		t.Errorf("source_ip = %q, want %q (port stripped)", recs[0].SourceIP, sourceIP)
	}

	// A non-matching source_ip filter returns no rows.
	empty, err := client.Get(ts.URL + "/api/sessions?source_ip=198.51.100.1")
	if err != nil {
		t.Fatalf("get sessions (no match): %v", err)
	}
	var none []monitor.Record
	json.NewDecoder(empty.Body).Decode(&none) //nolint:errcheck
	empty.Body.Close()
	if len(none) != 0 {
		t.Errorf("non-matching filter returned %d rows, want 0", len(none))
	}
}

// seedDisconnectWithBytes persists a disconnect connection_events row carrying a
// session byte delta and returns the device id and the bytes written.
func seedDisconnectWithBytes(t *testing.T, conn *sql.DB) (deviceID string, rx, tx uint64) {
	t.Helper()
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Name: "Carol", Email: "carol@example.com"})
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
	const pk = "BYTESpubkey00000000000000000000000000000000="
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: node.ID, DeviceID: device.ID, Protocol: "amneziawg", PublicKey: pk, AllowedIP: "10.86.0.10/32",
	}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}

	rx, tx = 8_400_000, 2_100_000
	store := monitor.NewStore(conn, nil)
	go store.Run(ctx)
	res := store.Resolve(ctx, pk)
	store.Ingest(monitor.Event{
		At: time.Now().UTC(), NodeID: node.ID, PeerID: pk,
		DeviceID: res.DeviceID, UserID: res.UserID, Protocol: "AMNEZIAWG",
		EventType: "disconnect", SourceIP: monitor.SourceIP("203.0.113.41:1194"),
		SourceEndpoint: "203.0.113.41:1194", RxBytes: rx, TxBytes: tx,
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		recs, err := monitor.Query(ctx, conn, monitor.Filter{DeviceID: device.ID})
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(recs) > 0 {
			return device.ID, rx, tx
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the disconnect row to persist")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSessionsReturnsSessionBytes: a disconnect event carrying a session byte
// delta persists non-zero rx/tx, and /api/sessions returns them in the JSON —
// the end of the pipeline that used to always report 0.
func TestSessionsReturnsSessionBytes(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	deviceID, wantRx, wantTx := seedDisconnectWithBytes(t, conn)

	resp, err := client.Get(ts.URL + "/api/sessions?device=" + deviceID)
	if err != nil {
		t.Fatalf("get sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sessions: status %d want 200", resp.StatusCode)
	}
	var recs []monitor.Record
	if err := json.NewDecoder(resp.Body).Decode(&recs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("sessions: got %d rows want 1", len(recs))
	}
	if recs[0].RxBytes != wantRx || recs[0].TxBytes != wantTx {
		t.Errorf("session bytes rx=%d tx=%d, want %d/%d (must not be 0)",
			recs[0].RxBytes, recs[0].TxBytes, wantRx, wantTx)
	}
}

// TestSessionsScope: /api/sessions is monitor-scoped — a readonly token is
// 403'd, a monitor token is allowed.
func TestSessionsScope(t *testing.T) {
	ts, _, conn := setup(t)

	ro, _, err := authn.Create(context.Background(), conn, "ro", authn.ScopeReadonly, 0, "test")
	if err != nil {
		t.Fatalf("Create readonly token: %v", err)
	}
	roResp := bearerReq(t, ts, http.MethodGet, "/api/sessions", ro, "")
	roResp.Body.Close()
	if roResp.StatusCode != http.StatusForbidden {
		t.Errorf("readonly /api/sessions: status %d want 403", roResp.StatusCode)
	}

	mon, _, err := authn.Create(context.Background(), conn, "mon", authn.ScopeMonitor, 0, "test")
	if err != nil {
		t.Fatalf("Create monitor token: %v", err)
	}
	monResp := bearerReq(t, ts, http.MethodGet, "/api/sessions", mon, "")
	monResp.Body.Close()
	if monResp.StatusCode != http.StatusOK {
		t.Errorf("monitor /api/sessions: status %d want 200", monResp.StatusCode)
	}
}
