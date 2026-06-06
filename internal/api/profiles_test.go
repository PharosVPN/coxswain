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
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/wg"
)

// TestProfilesAPI covers the profile CRUD endpoints: create (with re-provision),
// list (filtered by device), the invalid-egress 400, and delete.
func TestProfilesAPI(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	ctx := context.Background()

	// A user with an enrolled encryption key (so the re-provision seals), a
	// device, and a data-plane-ready node to egress at.
	user, err := account.CreateUser(ctx, conn, account.User{Email: "u@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	wrapped, err := e2e.WrapPrivateKey("pw", kp.Private)
	if err != nil {
		t.Fatalf("WrapPrivateKey: %v", err)
	}
	if err := account.SetEncryptionKey(ctx, conn, user.ID, kp.Public, wrapped); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "laptop"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "ny", Region: "us", PublicIP: "203.0.113.7",
		WGPublicKey: "bm9kZS1hbXMtd2cta2V5LWJhc2U2NA==",
		Obfuscation: wg.Obfuscation{Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 45, S3: 60, S4: 75, H1: 1, H2: 2, H3: 3, H4: 4},
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	// Create a direct AmneziaWG profile.
	body := `{"user_id":"` + user.ID + `","device_id":"` + device.ID + `","name":"US Direct","node_id":"` + node.ID + `","protocol":"amneziawg"}`
	resp, err := client.Post(ts.URL+"/api/profiles", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d", resp.StatusCode)
	}
	var view profileSpecView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if view.ID == "" || view.Name != "US Direct" || view.NodeID != node.ID || view.Protocol != "amneziawg" {
		t.Fatalf("created view wrong: %+v", view)
	}

	// The re-provision minted a peer tagged with the spec id.
	peers, err := fleet.ListPeersByDevice(ctx, conn, device.ID)
	if err != nil || len(peers) != 1 || peers[0].ProfileSpecID != view.ID {
		t.Fatalf("expected one peer tagged %s, got %+v (%v)", view.ID, peers, err)
	}

	// List, filtered by device.
	resp, err = client.Get(ts.URL + "/api/profiles?device=" + device.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var views []profileSpecView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	resp.Body.Close()
	if len(views) != 1 || views[0].ID != view.ID {
		t.Fatalf("list = %+v, want the one profile", views)
	}

	// Invalid: no egress → 400.
	bad := `{"user_id":"` + user.ID + `","device_id":"` + device.ID + `","name":"bad","protocol":"amneziawg"}`
	resp, err = client.Post(ts.URL+"/api/profiles", "application/json", strings.NewReader(bad))
	if err != nil {
		t.Fatalf("create bad: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create bad: status %d, want 400", resp.StatusCode)
	}

	// Delete.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/profiles/"+view.ID, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status %d, want 204", resp.StatusCode)
	}
	if specs, _ := fleet.ListProfileSpecsByDevice(ctx, conn, device.ID); len(specs) != 0 {
		t.Fatalf("profile not deleted: %+v", specs)
	}
}
