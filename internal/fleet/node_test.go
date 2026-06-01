// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/wg"
)

func TestNodeCRUD(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ams-1", Region: "europe-west4"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if created.ID == "" || created.Version != 1 {
		t.Fatalf("CreateNode: bad defaults %+v", created)
	}
	if created.Status != fleet.StatusPending {
		t.Errorf("status: got %q want %q", created.Status, fleet.StatusPending)
	}

	got, err := fleet.GetNode(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Name != "ams-1" || got.Region != "europe-west4" {
		t.Errorf("GetNode: got %+v", got)
	}

	list, err := fleet.ListNodes(ctx, conn)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListNodes: got %d want 1", len(list))
	}

	if err := fleet.DeleteNode(ctx, conn, created.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := fleet.GetNode(ctx, conn, created.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("GetNode after delete: got %v want ErrNotFound", err)
	}
}

func TestNextNodeConfigRevision(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ams-1", Region: "eu"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if created.ConfigRevision != 0 {
		t.Fatalf("fresh node config_revision: got %d want 0", created.ConfigRevision)
	}

	for want := int64(1); want <= 3; want++ {
		got, err := fleet.NextNodeConfigRevision(ctx, conn, created.ID)
		if err != nil {
			t.Fatalf("NextNodeConfigRevision: %v", err)
		}
		if got != want {
			t.Errorf("revision: got %d want %d", got, want)
		}
	}

	refreshed, err := fleet.GetNode(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if refreshed.ConfigRevision != 3 {
		t.Errorf("persisted revision: got %d want 3", refreshed.ConfigRevision)
	}

	if _, err := fleet.NextNodeConfigRevision(ctx, conn, "nod-missing"); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("missing node: got %v want ErrNotFound", err)
	}
}

func TestSetNodeAmneziaWG(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ams-1", Region: "eu"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	// A fresh node has reported no data-plane config yet.
	if !created.Obfuscation.IsZero() || created.WGPublicKey != "" {
		t.Fatalf("new node already has AmneziaWG config: %+v", created)
	}

	obf := wg.Obfuscation{
		Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 45, S3: 60, S4: 75,
		H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755,
		I1: "<b 0x00000000>",
	}
	if err := fleet.SetNodeAmneziaWG(ctx, conn, created.ID, "node-wg-pub-key", obf); err != nil {
		t.Fatalf("SetNodeAmneziaWG: %v", err)
	}

	got, err := fleet.GetNode(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.WGPublicKey != "node-wg-pub-key" {
		t.Errorf("wg public key: got %q", got.WGPublicKey)
	}
	if got.Obfuscation != obf {
		t.Errorf("obfuscation round trip: got %+v want %+v", got.Obfuscation, obf)
	}
	if got.Version != created.Version+1 {
		t.Errorf("version: got %d want %d", got.Version, created.Version+1)
	}

	if err := fleet.SetNodeAmneziaWG(ctx, conn, "nod-missing", "k", obf); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("SetNodeAmneziaWG on missing node: got %v want ErrNotFound", err)
	}

	// A structurally invalid obfuscation set is rejected at ingest, before
	// it can land on the node row.
	bad := obf
	bad.H4 = bad.H1 // colliding magic headers
	if err := fleet.SetNodeAmneziaWG(ctx, conn, created.ID, "k", bad); err == nil {
		t.Fatal("SetNodeAmneziaWG accepted an invalid obfuscation set")
	}
}

func TestUpdateNodeOptimisticConcurrency(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	n, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "ams-1", Region: "eu"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	// Two admins load the same version.
	stale := n

	// Admin A updates successfully; the version bumps to 2.
	n.Status = fleet.StatusActive
	n.PublicIP = "203.0.113.7"
	updated, err := fleet.UpdateNode(ctx, conn, n)
	if err != nil {
		t.Fatalf("UpdateNode (fresh): %v", err)
	}
	if updated.Version != 2 {
		t.Errorf("version: got %d want 2", updated.Version)
	}

	// Admin B writes against the stale version 1 — must be rejected.
	stale.Status = fleet.StatusStopped
	if _, err := fleet.UpdateNode(ctx, conn, stale); !errors.Is(err, fleet.ErrStaleVersion) {
		t.Fatalf("UpdateNode (stale): got %v want ErrStaleVersion", err)
	}

	// The successful write stuck.
	got, err := fleet.GetNode(ctx, conn, n.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Status != fleet.StatusActive || got.PublicIP != "203.0.113.7" {
		t.Errorf("GetNode: stale write leaked through: %+v", got)
	}
}

func TestUpdateNodeNotFound(t *testing.T) {
	conn := newDB(t)
	_, err := fleet.UpdateNode(context.Background(), conn,
		fleet.Node{ID: "nod_missing", Version: 1})
	if !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestDeleteNodeNotFound(t *testing.T) {
	conn := newDB(t)
	if err := fleet.DeleteNode(context.Background(), conn, "nod_missing"); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}
