// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestControlPathsEndpoints(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	ctx := context.Background()

	postCP := func(body string) (*http.Response, controlPathView) {
		t.Helper()
		resp, err := client.Post(ts.URL+"/api/control-paths", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post control-paths: %v", err)
		}
		var v controlPathView
		_ = json.NewDecoder(resp.Body).Decode(&v)
		resp.Body.Close()
		return resp, v
	}

	// Starts empty.
	resp, err := client.Get(ts.URL + "/api/control-paths")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var list []controlPathView
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list) != 0 {
		t.Fatalf("list: status %d, %d rows", resp.StatusCode, len(list))
	}

	// Create a direct path (no hops).
	resp, direct := postCP(`{"name":"direct"}`)
	if resp.StatusCode != http.StatusCreated || direct.Active || len(direct.Hops) != 0 {
		t.Fatalf("create direct: status %d, active %v, hops %v", resp.StatusCode, direct.Active, direct.Hops)
	}

	// A hop through an unknown relay is rejected.
	if resp, _ := postCP(`{"name":"bad","hops":["rly_nope"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with unknown relay: got %d want 400", resp.StatusCode)
	}

	// Empty name is rejected.
	if resp, _ := postCP(`{"name":""}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with empty name: got %d want 400", resp.StatusCode)
	}

	// Seed a relay and create a path through it.
	relay, err := fleet.CreateRelay(ctx, conn, fleet.Relay{Name: "edge", Kind: fleet.RelayKindRemote})
	if err != nil {
		t.Fatalf("seed relay: %v", err)
	}
	resp, via := postCP(`{"name":"via-edge","hops":["` + relay.ID + `"]}`)
	if resp.StatusCode != http.StatusCreated || len(via.Hops) != 1 || via.Hops[0] != relay.ID {
		t.Fatalf("create via-edge: status %d, hops %v", resp.StatusCode, via.Hops)
	}

	// Activate via-edge → it becomes the single active path.
	resp, err = client.Post(ts.URL+"/api/control-paths/"+via.ID+"/activate", "application/json", nil)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	var activated controlPathView
	_ = json.NewDecoder(resp.Body).Decode(&activated)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !activated.Active {
		t.Fatalf("activate via-edge: status %d, active %v", resp.StatusCode, activated.Active)
	}

	// Exactly one active in the list.
	resp, _ = client.Get(ts.URL + "/api/control-paths")
	_ = json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	activeCount := 0
	for _, p := range list {
		if p.Active {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Fatalf("active count = %d, want 1", activeCount)
	}

	// Swap to direct, then removing the active one is allowed (falls back to direct).
	resp, err = client.Post(ts.URL+"/api/control-paths/"+direct.ID+"/activate", "application/json", nil)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	resp.Body.Close()
	if got := del(t, client, ts.URL+"/api/control-paths/"+direct.ID); got != http.StatusNoContent {
		t.Fatalf("delete active path: got %d want 204", got)
	}

	// Missing paths are 404 for activate and delete.
	resp, err = client.Post(ts.URL+"/api/control-paths/cpath_missing/activate", "application/json", nil)
	if err != nil {
		t.Fatalf("activate missing: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("activate missing: got %d want 404", resp.StatusCode)
	}
	if got := del(t, client, ts.URL+"/api/control-paths/cpath_missing"); got != http.StatusNotFound {
		t.Fatalf("delete missing: got %d want 404", got)
	}
}
