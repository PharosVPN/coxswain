// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestRelayCRUD(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateRelay(ctx, conn, fleet.Relay{
		Name: "edge-1", Kind: fleet.RelayKindRemote, Endpoint: "relay.example.net:8444",
	})
	if err != nil {
		t.Fatalf("CreateRelay: %v", err)
	}
	if created.ID == "" || created.Version != 1 {
		t.Fatalf("CreateRelay: bad defaults %+v", created)
	}
	if created.Status != fleet.StatusPending {
		t.Errorf("status: got %q want %q", created.Status, fleet.StatusPending)
	}

	got, err := fleet.GetRelay(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetRelay: %v", err)
	}
	if got.Name != "edge-1" || got.Endpoint != "relay.example.net:8444" {
		t.Errorf("GetRelay: got %+v", got)
	}

	// Promote it to active under optimistic concurrency.
	got.Status = fleet.StatusActive
	updated, err := fleet.UpdateRelay(ctx, conn, got)
	if err != nil {
		t.Fatalf("UpdateRelay: %v", err)
	}
	if updated.Version != 2 {
		t.Errorf("version: got %d want 2", updated.Version)
	}
	if _, err := fleet.UpdateRelay(ctx, conn, got); !errors.Is(err, fleet.ErrStaleVersion) {
		t.Fatalf("stale UpdateRelay: got %v want ErrStaleVersion", err)
	}

	list, err := fleet.ListRelays(ctx, conn)
	if err != nil {
		t.Fatalf("ListRelays: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListRelays: got %d want 1", len(list))
	}

	if err := fleet.DeleteRelay(ctx, conn, created.ID); err != nil {
		t.Fatalf("DeleteRelay: %v", err)
	}
	if _, err := fleet.GetRelay(ctx, conn, created.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("GetRelay after delete: got %v want ErrNotFound", err)
	}
	if err := fleet.DeleteRelay(ctx, conn, created.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("DeleteRelay missing: got %v want ErrNotFound", err)
	}
}

// TestRelayEgressFields round-trips the control-plane egress fields (decision
// 19): a relay's egress endpoint and chain hop survive create, get and update.
func TestRelayEgressFields(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateRelay(ctx, conn, fleet.Relay{
		Name: "egress-2", Kind: fleet.RelayKindRemote, Endpoint: "r2.example:8444",
		EgressEndpoint: "r2.example:8456", EgressHop: 2,
	})
	if err != nil {
		t.Fatalf("CreateRelay: %v", err)
	}

	got, err := fleet.GetRelay(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetRelay: %v", err)
	}
	if got.EgressEndpoint != "r2.example:8456" || got.EgressHop != 2 {
		t.Errorf("egress fields not persisted: endpoint=%q hop=%d", got.EgressEndpoint, got.EgressHop)
	}

	// Re-order the hop under optimistic concurrency.
	got.EgressHop = 5
	updated, err := fleet.UpdateRelay(ctx, conn, got)
	if err != nil {
		t.Fatalf("UpdateRelay: %v", err)
	}
	if updated.EgressHop != 5 {
		t.Errorf("EgressHop after update: got %d want 5", updated.EgressHop)
	}
	reread, _ := fleet.GetRelay(ctx, conn, created.ID)
	if reread.EgressHop != 5 || reread.EgressEndpoint != "r2.example:8456" {
		t.Errorf("re-read egress fields: endpoint=%q hop=%d", reread.EgressEndpoint, reread.EgressHop)
	}
}

func TestCreateRelayRejectsBadKind(t *testing.T) {
	conn := newDB(t)
	if _, err := fleet.CreateRelay(context.Background(), conn, fleet.Relay{
		Name: "bogus", Kind: "satellite",
	}); err == nil {
		t.Fatal("CreateRelay accepted an invalid kind")
	}
}
