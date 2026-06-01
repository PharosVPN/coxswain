// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func mustNode(t *testing.T, conn *sql.DB, name string) fleet.Node {
	t.Helper()
	n, err := fleet.CreateNode(context.Background(), conn, fleet.Node{Name: name, Region: "eu"})
	if err != nil {
		t.Fatalf("CreateNode(%s): %v", name, err)
	}
	return n
}

func TestCreateNodeLinkAllocatesResources(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mustNode(t, conn, "entry")
	exitA := mustNode(t, conn, "exit-a")
	exitB := mustNode(t, conn, "exit-b")

	a, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exitA.ID, "PSK-A=")
	if err != nil {
		t.Fatalf("CreateNodeLink A: %v", err)
	}
	if a.InnerInterface != "awg1" || a.ListenPort == 0 || a.Fwmark == 0 || a.TableID == 0 {
		t.Fatalf("first link bad allocation: %+v", a)
	}
	if a.Status != "pending" || a.Version != 1 || a.ConfigRevision != 0 {
		t.Errorf("first link bad defaults: %+v", a)
	}

	// A second link from the same entry gets the next free index — distinct
	// interface, port, mark and table.
	b, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exitB.ID, "PSK-B=")
	if err != nil {
		t.Fatalf("CreateNodeLink B: %v", err)
	}
	if b.InnerInterface != "awg2" {
		t.Errorf("second link interface = %q, want awg2", b.InnerInterface)
	}
	if b.ListenPort == a.ListenPort || b.Fwmark == a.Fwmark || b.TableID == a.TableID {
		t.Errorf("second link resources collide with first: a=%+v b=%+v", a, b)
	}
}

func TestCreateNodeLinkRejectsSelfAndDuplicate(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mustNode(t, conn, "entry")
	exit := mustNode(t, conn, "exit")

	if _, err := fleet.CreateNodeLink(ctx, conn, entry.ID, entry.ID, ""); !errors.Is(err, fleet.ErrSelfLink) {
		t.Errorf("self link: got %v, want ErrSelfLink", err)
	}
	if _, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exit.ID, ""); err != nil {
		t.Fatalf("first edge: %v", err)
	}
	if _, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exit.ID, ""); !errors.Is(err, fleet.ErrLinkExists) {
		t.Errorf("duplicate edge: got %v, want ErrLinkExists", err)
	}
}

func TestNodeLinkGetListAndRevision(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mustNode(t, conn, "entry")
	exit := mustNode(t, conn, "exit")

	created, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exit.ID, "PSK=")
	if err != nil {
		t.Fatalf("CreateNodeLink: %v", err)
	}

	got, err := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, exit.ID)
	if err != nil || got.ID != created.ID {
		t.Fatalf("GetNodeLinkByEdge: %+v, %v", got, err)
	}
	links, err := fleet.ListNodeLinksByEntry(ctx, conn, entry.ID)
	if err != nil || len(links) != 1 {
		t.Fatalf("ListNodeLinksByEntry: %d links, %v", len(links), err)
	}

	// The config revision is a monotonic counter.
	for want := int64(1); want <= 3; want++ {
		rev, err := fleet.NextNodeLinkConfigRevision(ctx, conn, created.ID)
		if err != nil || rev != want {
			t.Fatalf("NextNodeLinkConfigRevision: got %d (%v), want %d", rev, err, want)
		}
	}

	if err := fleet.DeleteNodeLink(ctx, conn, created.ID); err != nil {
		t.Fatalf("DeleteNodeLink: %v", err)
	}
	if _, err := fleet.GetNodeLink(ctx, conn, created.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestNodeLinkCascadeDeleteWithNode(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mustNode(t, conn, "entry")
	exit := mustNode(t, conn, "exit")
	if _, err := fleet.CreateNodeLink(ctx, conn, entry.ID, exit.ID, ""); err != nil {
		t.Fatalf("CreateNodeLink: %v", err)
	}
	// Deleting the exit node cascades to its links (FK ON DELETE CASCADE).
	if err := fleet.DeleteNode(ctx, conn, exit.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	links, err := fleet.ListNodeLinks(ctx, conn)
	if err != nil {
		t.Fatalf("ListNodeLinks: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("links should cascade-delete with the node, got %d", len(links))
	}
}
