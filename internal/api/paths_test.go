// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestPathsEndpoints(t *testing.T) {
	ts, client, conn := setup(t) // setup wires a nil PathCoordinator
	login(t, ts, client)
	ctx := context.Background()

	// GET is available without a coordinator; starts empty.
	resp, err := client.Get(ts.URL + "/api/paths")
	if err != nil {
		t.Fatalf("get paths: %v", err)
	}
	var list []pathView
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list) != 0 {
		t.Fatalf("list paths: status %d, %d rows", resp.StatusCode, len(list))
	}

	// Defining/provisioning a path needs a coordinator (none in tests) → 503.
	resp, err = client.Post(ts.URL+"/api/paths", "application/json",
		strings.NewReader(`{"name":"p","node_ids":["a","b"]}`))
	if err != nil {
		t.Fatalf("post paths: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("create path without coordinator: got %d want 503", resp.StatusCode)
	}

	// Binding a device likewise needs a coordinator → 503.
	resp, err = client.Post(ts.URL+"/api/devices/dev_x/bind", "application/json",
		strings.NewReader(`{"path_id":"pth_x"}`))
	if err != nil {
		t.Fatalf("post bind: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bind without coordinator: got %d want 503", resp.StatusCode)
	}

	// Seed two nodes + a path; a path with a bound client cannot be removed (409),
	// even though teardown itself is unavailable — the safety block comes first.
	entry, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "entry", Region: "nyc1"})
	if err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	exit, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "exit", Region: "ams3"})
	if err != nil {
		t.Fatalf("seed exit: %v", err)
	}
	bound, err := fleet.CreatePath(ctx, conn, "bound", "", []string{entry.ID, exit.ID})
	if err != nil {
		t.Fatalf("seed path: %v", err)
	}
	user, err := account.CreateUser(ctx, conn, account.User{Email: "u@x.test"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	dev, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "phone"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := fleet.SetDeviceExit(ctx, conn, dev.ID, bound.ID); err != nil {
		t.Fatalf("bind device: %v", err)
	}
	if got := del(t, client, ts.URL+"/api/paths/"+bound.ID); got != http.StatusConflict {
		t.Fatalf("delete path with a bound client: got %d want 409", got)
	}

	// A path with no clients reaches the teardown, which is unavailable → 503.
	free, err := fleet.CreatePath(ctx, conn, "free", "", []string{entry.ID, exit.ID})
	if err != nil {
		t.Fatalf("seed free path: %v", err)
	}
	if got := del(t, client, ts.URL+"/api/paths/"+free.ID); got != http.StatusServiceUnavailable {
		t.Fatalf("delete free path without coordinator: got %d want 503", got)
	}

	// A missing path is 404.
	if got := del(t, client, ts.URL+"/api/paths/pth_missing"); got != http.StatusNotFound {
		t.Fatalf("delete missing path: got %d want 404", got)
	}
}
