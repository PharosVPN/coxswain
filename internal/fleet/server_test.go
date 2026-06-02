// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestServerCRUD(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	created, err := fleet.CreateServer(ctx, conn, fleet.Server{
		Name: "edge", Region: "nyc1", SSHHost: "203.0.113.10", SSHUser: "root", SSHHostKey: "ssh-ed25519 AAAA…",
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if created.ID == "" || created.Version != 1 || created.SSHPort != 22 {
		t.Fatalf("CreateServer defaults: %+v", created)
	}
	if created.Status != fleet.StatusPending {
		t.Errorf("status: got %q want %q", created.Status, fleet.StatusPending)
	}

	got, err := fleet.GetServer(ctx, conn, created.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.SSHHost != "203.0.113.10" || got.SSHHostKey != "ssh-ed25519 AAAA…" || got.IsSelf {
		t.Errorf("GetServer round-trip: %+v", got)
	}

	// Idempotent re-onboard lookup by host.
	byHost, err := fleet.GetServerByHost(ctx, conn, "203.0.113.10")
	if err != nil || byHost.ID != created.ID {
		t.Fatalf("GetServerByHost: %+v, %v", byHost, err)
	}

	if err := fleet.SetServerStatus(ctx, conn, created.ID, fleet.StatusActive); err != nil {
		t.Fatalf("SetServerStatus: %v", err)
	}

	// A self server is single and round-trips its flag.
	self, err := fleet.CreateServer(ctx, conn, fleet.Server{Name: "controller", SSHHost: "10.0.0.1", SSHUser: "root", IsSelf: true})
	if err != nil {
		t.Fatalf("CreateServer self: %v", err)
	}
	gotSelf, err := fleet.GetSelfServer(ctx, conn)
	if err != nil || gotSelf.ID != self.ID || !gotSelf.IsSelf {
		t.Fatalf("GetSelfServer: %+v, %v", gotSelf, err)
	}

	// Deleting a server with a node deployed onto it is refused.
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "n1", Region: "nyc1", ServerID: created.ID})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if node.ServerID != created.ID {
		t.Errorf("node server_id round-trip: got %q want %q", node.ServerID, created.ID)
	}
	if err := fleet.DeleteServer(ctx, conn, created.ID); !errors.Is(err, fleet.ErrServerInUse) {
		t.Fatalf("DeleteServer in use: got %v want ErrServerInUse", err)
	}
	if err := fleet.DeleteNode(ctx, conn, node.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if err := fleet.DeleteServer(ctx, conn, created.ID); err != nil {
		t.Fatalf("DeleteServer after freeing: %v", err)
	}
	if _, err := fleet.GetServer(ctx, conn, created.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("GetServer after delete: got %v want ErrNotFound", err)
	}
}
