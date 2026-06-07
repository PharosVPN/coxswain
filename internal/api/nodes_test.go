// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

// setupWithPusher builds a test server, optionally wiring a node pusher, and
// returns the server, a logged-in client, the db, and the *Server so the test
// can inspect injected state.
func setupWithPusher(t *testing.T, pusher NodePusher) (*httptest.Server, *http.Client, *Server) {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	if err := auth.SyncConfigAdmin(context.Background(), conn, testAdminPassword); err != nil {
		t.Fatalf("SyncConfigAdmin: %v", err)
	}
	srv := NewServer("", conn, live.NewHub(), provision.Options{
		VPNSubnet: "10.86.0.0/16", PortMin: 2000, PortMax: 60000,
	}, nil, nil, nil, "")
	if pusher != nil {
		srv.SetNodePusher(pusher)
	}
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	login(t, ts, client)
	return ts, client, srv
}

// TestPushNodeRouteUnavailable: with no pusher wired, the reconcile route reports
// 503 rather than pretending to succeed.
func TestPushNodeRouteUnavailable(t *testing.T) {
	ts, client, srv := setupWithPusher(t, nil)
	node, err := fleet.CreateNode(context.Background(), srv.db, fleet.Node{
		Name: "n", Region: "eu", ControlAddr: "n:8444", PublicIP: "203.0.113.5",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	resp, err := client.Post(ts.URL+"/api/nodes/"+node.ID+"/push", "application/json", nil)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

// TestPushNodeRoute: with a pusher wired, the route invokes it for the node and
// returns its result as JSON. A missing node yields 404 without calling it.
func TestPushNodeRoute(t *testing.T) {
	var pushedID string
	pusher := func(_ context.Context, nodeID string) (any, error) {
		pushedID = nodeID
		return map[string]any{"amnezia_peers": 3, "reloaded": true}, nil
	}
	ts, client, srv := setupWithPusher(t, pusher)

	node, err := fleet.CreateNode(context.Background(), srv.db, fleet.Node{
		Name: "ny", Region: "us", ControlAddr: "ny:8444", PublicIP: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	resp, err := client.Post(ts.URL+"/api/nodes/"+node.ID+"/push", "application/json", nil)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if pushedID != node.ID {
		t.Errorf("pusher called with %q, want %q", pushedID, node.ID)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["reloaded"] != true {
		t.Errorf("response body = %v, want reloaded true", body)
	}

	// A missing node is a 404 and never reaches the pusher.
	pushedID = ""
	miss, err := client.Post(ts.URL+"/api/nodes/nope/push", "application/json", nil)
	if err != nil {
		t.Fatalf("push missing: %v", err)
	}
	defer miss.Body.Close()
	if miss.StatusCode != http.StatusNotFound {
		t.Errorf("missing node status = %d, want 404", miss.StatusCode)
	}
	if pushedID != "" {
		t.Errorf("pusher should not be called for a missing node, got %q", pushedID)
	}
}
