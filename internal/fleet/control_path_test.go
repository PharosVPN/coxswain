// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestControlPathCRUDAndActivation(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)

	// No active path yet → direct (nil hops).
	if hops := fleet.ActiveControlPathHops(ctx, conn); hops != nil {
		t.Fatalf("no path: ActiveControlPathHops = %v, want nil (direct)", hops)
	}
	if _, err := fleet.GetActiveControlPath(ctx, conn); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("no path: GetActiveControlPath err = %v, want ErrNotFound", err)
	}

	// Create two paths — both start INACTIVE regardless of the Active field.
	direct, err := fleet.CreateControlPath(ctx, conn, fleet.ControlPath{Name: "direct"})
	if err != nil {
		t.Fatalf("create direct: %v", err)
	}
	if direct.Active {
		t.Error("new control path should be created inactive")
	}
	viaAms, err := fleet.CreateControlPath(ctx, conn, fleet.ControlPath{Name: "via-ams", Hops: []string{"rly_a", "rly_b"}, Active: true})
	if err != nil {
		t.Fatalf("create via-ams: %v", err)
	}
	if viaAms.Active {
		t.Error("Active=true on create must be ignored (activation is explicit)")
	}

	if list, err := fleet.ListControlPaths(ctx, conn); err != nil || len(list) != 2 {
		t.Fatalf("list: got %d paths (err %v), want 2", len(list), err)
	}

	// Activate via-ams → it becomes the fleet route; hops resolve through it.
	if err := fleet.SetActiveControlPath(ctx, conn, viaAms.ID); err != nil {
		t.Fatalf("activate via-ams: %v", err)
	}
	active, err := fleet.GetActiveControlPath(ctx, conn)
	if err != nil || active.ID != viaAms.ID {
		t.Fatalf("active path = %v (err %v), want %s", active.ID, err, viaAms.ID)
	}
	if hops := fleet.ActiveControlPathHops(ctx, conn); len(hops) != 2 || hops[0] != "rly_a" || hops[1] != "rly_b" {
		t.Fatalf("active hops = %v, want [rly_a rly_b]", hops)
	}

	// Swap to direct → exactly one active (the partial-unique index holds), hops empty.
	if err := fleet.SetActiveControlPath(ctx, conn, direct.ID); err != nil {
		t.Fatalf("swap to direct: %v", err)
	}
	active, _ = fleet.GetActiveControlPath(ctx, conn)
	if active.ID != direct.ID {
		t.Errorf("after swap active = %s, want %s (direct)", active.ID, direct.ID)
	}
	if hops := fleet.ActiveControlPathHops(ctx, conn); hops != nil {
		t.Errorf("direct active hops = %v, want nil", hops)
	}
	// The old active must have been deactivated (no second active row).
	got, _ := fleet.GetControlPath(ctx, conn, viaAms.ID)
	if got.Active {
		t.Error("swapping should have deactivated via-ams")
	}

	// Optimistic update of hops.
	viaAms, _ = fleet.GetControlPath(ctx, conn, viaAms.ID)
	stale := viaAms // capture pre-bump version
	viaAms.Hops = []string{"rly_a", "rly_b", "rly_c"}
	if _, err := fleet.UpdateControlPath(ctx, conn, viaAms); err != nil {
		t.Fatalf("update hops: %v", err)
	}
	if _, err := fleet.UpdateControlPath(ctx, conn, stale); !errors.Is(err, fleet.ErrStaleVersion) {
		t.Fatalf("stale update err = %v, want ErrStaleVersion", err)
	}

	// Activating a missing path is ErrNotFound; deleting works.
	if err := fleet.SetActiveControlPath(ctx, conn, "cpath_nope"); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("activate missing err = %v, want ErrNotFound", err)
	}
	if err := fleet.DeleteControlPath(ctx, conn, viaAms.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := fleet.GetControlPath(ctx, conn, viaAms.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("get deleted err = %v, want ErrNotFound", err)
	}
}
