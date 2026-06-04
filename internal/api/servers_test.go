// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestServersEndpoints(t *testing.T) {
	ts, client, conn := setup(t) // setup wires a nil Deployer
	login(t, ts, client)

	// GET is available even without a deployer; starts empty.
	resp, err := client.Get(ts.URL + "/api/servers")
	if err != nil {
		t.Fatalf("get servers: %v", err)
	}
	var list []serverView
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list) != 0 {
		t.Fatalf("list servers: status %d, %d rows", resp.StatusCode, len(list))
	}

	// Onboard and deploy require a deployer (none in tests) → 503.
	resp, err = client.Post(ts.URL+"/api/servers", "application/json",
		strings.NewReader(`{"ssh_host":"203.0.113.10","ssh_user":"root","password":"x"}`))
	if err != nil {
		t.Fatalf("post servers: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("onboard without deployer: got %d want 503", resp.StatusCode)
	}

	// Removing a server cascades to the node/relay records on it (forget-from-
	// inventory), so a server whose machine is gone can be cleaned up in one go.
	ctx := context.Background()
	srv, err := fleet.CreateServer(ctx, conn, fleet.Server{
		Name: "edge", SSHHost: "203.0.113.10", SSHUser: "root", Status: fleet.StatusActive,
	})
	if err != nil {
		t.Fatalf("seed server: %v", err)
	}
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "n1", Region: "nyc1", ServerID: srv.ID})
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if got := del(t, client, ts.URL+"/api/servers/"+srv.ID); got != http.StatusNoContent {
		t.Fatalf("delete server: got %d want 204", got)
	}
	if _, err := fleet.GetServer(ctx, conn, srv.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("server should be gone: %v", err)
	}
	if _, err := fleet.GetNode(ctx, conn, node.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("node on server should be cascade-removed: %v", err)
	}

	// The self server cannot be removed (409); a missing server is 404.
	self, err := fleet.CreateServer(ctx, conn, fleet.Server{Name: "controller", SSHHost: "10.0.0.1", SSHUser: "root", IsSelf: true})
	if err != nil {
		t.Fatalf("seed self: %v", err)
	}
	if got := del(t, client, ts.URL+"/api/servers/"+self.ID); got != http.StatusConflict {
		t.Fatalf("delete self server: got %d want 409", got)
	}
	if got := del(t, client, ts.URL+"/api/servers/srv_missing"); got != http.StatusNotFound {
		t.Fatalf("delete missing server: got %d want 404", got)
	}
}

func del(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
