// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestProfileSpecCRUD(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	// A direct (single-node) XRay profile with an entry-IP subset.
	spec, err := fleet.CreateProfileSpec(ctx, conn, fleet.ProfileSpec{
		UserID:   "usr_1",
		DeviceID: "dev_1",
		Name:     "Stealth NYC",
		NodeID:   "nod_nyc",
		EntryIPs: []string{"1.1.1.1", "2.2.2.2"},
		Protocol: fleet.ProtoXRayReality,
	})
	if err != nil {
		t.Fatalf("CreateProfileSpec: %v", err)
	}
	if spec.ID == "" || spec.Version != 1 {
		t.Fatalf("spec not initialized: %+v", spec)
	}

	got, err := fleet.GetProfileSpec(ctx, conn, spec.ID)
	if err != nil {
		t.Fatalf("GetProfileSpec: %v", err)
	}
	if got.Name != "Stealth NYC" || got.NodeID != "nod_nyc" || got.Protocol != fleet.ProtoXRayReality {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(got.EntryIPs) != 2 || got.EntryIPs[0] != "1.1.1.1" {
		t.Fatalf("entry IPs not preserved: %v", got.EntryIPs)
	}

	// A second profile on the same device — a cascade (path) AmneziaWG one.
	if _, err := fleet.CreateProfileSpec(ctx, conn, fleet.ProfileSpec{
		UserID: "usr_1", DeviceID: "dev_1", Name: "EU Cascade",
		PathID: "pth_eu", Protocol: fleet.ProtoAmneziaWG,
	}); err != nil {
		t.Fatalf("CreateProfileSpec 2: %v", err)
	}

	byDev, err := fleet.ListProfileSpecsByDevice(ctx, conn, "dev_1")
	if err != nil || len(byDev) != 2 {
		t.Fatalf("ListProfileSpecsByDevice = %d (%v), want 2", len(byDev), err)
	}
	byUser, err := fleet.ListProfileSpecsByUser(ctx, conn, "usr_1")
	if err != nil || len(byUser) != 2 {
		t.Fatalf("ListProfileSpecsByUser = %d (%v), want 2", len(byUser), err)
	}

	if err := fleet.DeleteProfileSpec(ctx, conn, spec.ID); err != nil {
		t.Fatalf("DeleteProfileSpec: %v", err)
	}
	if _, err := fleet.GetProfileSpec(ctx, conn, spec.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestProfileSpecValidation(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	base := fleet.ProfileSpec{UserID: "u", DeviceID: "d", Name: "n", NodeID: "nod", Protocol: fleet.ProtoAmneziaWG}

	cases := map[string]fleet.ProfileSpec{
		"no name":        {UserID: "u", DeviceID: "d", NodeID: "nod", Protocol: fleet.ProtoAmneziaWG},
		"no egress":      {UserID: "u", DeviceID: "d", Name: "n", Protocol: fleet.ProtoAmneziaWG},
		"both egress":    {UserID: "u", DeviceID: "d", Name: "n", NodeID: "nod", PathID: "pth", Protocol: fleet.ProtoAmneziaWG},
		"bad protocol":   {UserID: "u", DeviceID: "d", Name: "n", NodeID: "nod", Protocol: "wireguard"},
		"no user/device": {Name: "n", NodeID: "nod", Protocol: fleet.ProtoAmneziaWG},
	}
	for name, spec := range cases {
		if _, err := fleet.CreateProfileSpec(ctx, conn, spec); !errors.Is(err, fleet.ErrInvalidProfileSpec) {
			t.Errorf("%s: got %v, want ErrInvalidProfileSpec", name, err)
		}
	}
	// The valid base succeeds.
	if _, err := fleet.CreateProfileSpec(ctx, conn, base); err != nil {
		t.Errorf("valid spec rejected: %v", err)
	}
}
