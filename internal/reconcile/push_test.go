// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package reconcile

import (
	"context"
	"database/sql"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/wg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakePushClient records the control RPCs the push core makes to a node, and can
// simulate a node without REALITY support (Unimplemented) on the XRay push.
type fakePushClient struct {
	awgPeers    []*nodev1.Peer
	awgRevision int64
	xrayPeers   []*nodev1.Peer
	xrayCalled  bool
	xrayUnimpl  bool
	appliedRev  int64
	reloaded    bool
}

func (f *fakePushClient) PushAmneziaWGConfig(_ context.Context, rev int64, peers []*nodev1.Peer) (*nodev1.PushConfigResponse, error) {
	f.awgPeers = peers
	f.awgRevision = rev
	return &nodev1.PushConfigResponse{AppliedRevision: f.appliedRev, Reloaded: f.reloaded}, nil
}

func (f *fakePushClient) PushXRayRealityConfig(_ context.Context, rev int64, peers []*nodev1.Peer, _ string, _, _ []string, _ uint32) (*nodev1.PushConfigResponse, error) {
	f.xrayCalled = true
	f.xrayPeers = peers
	if f.xrayUnimpl {
		return nil, status.Error(codes.Unimplemented, "no REALITY support")
	}
	return &nodev1.PushConfigResponse{AppliedRevision: rev, Reloaded: true}, nil
}

// --- a fake cascade fleet, mirroring internal/cascade's test doubles ----------

type fakeNode struct {
	addPeer    []*nodev1.Peer
	removePeer []string
}

func (f *fakeNode) ConfigureInnerLink(_ context.Context, cfg *nodev1.InnerLinkConfig, rev int64) (*nodev1.ConfigureInnerLinkResponse, error) {
	return &nodev1.ConfigureInnerLinkResponse{AppliedRevision: rev, Reloaded: true}, nil
}
func (f *fakeNode) RemoveInnerLink(_ context.Context, iface string) (*nodev1.RemoveInnerLinkResponse, error) {
	return &nodev1.RemoveInnerLinkResponse{Removed: true}, nil
}
func (f *fakeNode) AddPeer(_ context.Context, p *nodev1.Peer) (*nodev1.PeerResponse, error) {
	f.addPeer = append(f.addPeer, p)
	return &nodev1.PeerResponse{Applied: true}, nil
}
func (f *fakeNode) RemovePeer(_ context.Context, _ nodev1.Protocol, pub string) (*nodev1.PeerResponse, error) {
	f.removePeer = append(f.removePeer, pub)
	return &nodev1.PeerResponse{Applied: true}, nil
}
func (f *fakeNode) SetNetworkConfig(_ context.Context, _, _, _ bool, _ []*nodev1.TransitRoute) (*nodev1.SetNetworkConfigResponse, error) {
	return &nodev1.SetNetworkConfigResponse{Applied: true}, nil
}
func (f *fakeNode) Close() error { return nil }

type fakeFleet struct{ nodes map[string]*fakeNode }

func newFleet() *fakeFleet { return &fakeFleet{nodes: map[string]*fakeNode{}} }
func (f *fakeFleet) dial(addr string) (cascade.NodeClient, error) {
	n, ok := f.nodes[addr]
	if !ok {
		n = &fakeNode{}
		f.nodes[addr] = n
	}
	return n, nil
}

func validObf() wg.Obfuscation {
	return wg.Obfuscation{Jc: 5, Jmin: 25, Jmax: 800, S1: 20, S2: 30, S3: 40, S4: 50, H1: 10, H2: 11, H3: 12, H4: 13}
}

func mkNode(t *testing.T, conn *sql.DB, name, ctrl, ip, pub string) fleet.Node {
	t.Helper()
	n, err := fleet.CreateNode(context.Background(), conn, fleet.Node{
		Name: name, Region: "r", ControlAddr: ctrl, PublicIP: ip,
		EndpointIPs: []string{ip}, WGPublicKey: pub, Obfuscation: validObf(),
	})
	if err != nil {
		t.Fatalf("create node %s: %v", name, err)
	}
	return n
}

// mkDeviceOn creates a user+device with a tunnel peer on a node and returns the
// device id — the cascaded source whose tunnel CIDR the exit edge peer must carry.
func mkDeviceOn(t *testing.T, conn *sql.DB, nodeID, email, devPub, allowedIP string) string {
	t.Helper()
	ctx := context.Background()
	user, err := account.CreateUser(ctx, conn, account.User{Email: email})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "dev"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: nodeID, DeviceID: dev.ID, Protocol: "amneziawg",
		PublicKey: devPub, AllowedIP: allowedIP,
	}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	return dev.ID
}

// TestPushNodeReappliesCascadeEdgePeers proves the load-bearing Phase 2
// invariant carried over from the inline push: after the AmneziaWG full-replace,
// PushNode re-applies the cascade edge peer on an exit hop (the entry's key
// carrying the cascaded device's tunnel CIDR) — the peer the replace wipes. It
// reuses internal/cascade's fake-fleet pattern: a real Coordinator over fake
// nodes, with a real provisioned 2-hop path bound to a device.
func TestPushNodeReappliesCascadeEdgePeers(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "2.2.2.2", "EXITPUB=")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	// A 2-hop path entry->exit, provisioned, with a device bound that has its
	// tunnel on the entry — so the exit must carry the entry's key as an edge peer.
	p, err := fleet.CreatePath(ctx, conn, "p", "", []string{entry.ID, exit.ID})
	if err != nil {
		t.Fatalf("CreatePath: %v", err)
	}
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	dev := mkDeviceOn(t, conn, entry.ID, "u@x", "DEVPUB=", "10.86.0.5")
	if err := coord.BindDeviceToPath(ctx, dev, p.ID); err != nil {
		t.Fatalf("BindDeviceToPath: %v", err)
	}

	// Reset the recorded edge-peer calls so we observe only what the push re-applies.
	exitFake := ff.nodes["exit:8444"]
	exitFake.addPeer = nil

	// Push the entry node (a device-peer push that full-replaces its awg0). The
	// fake control client stands in for the dialed node; the real coordinator is
	// the injected cascade reconciler.
	cfg := &config.Config{Posture: config.PosturePersonal, StateDir: "."}
	client := &fakePushClient{appliedRev: 7, reloaded: true}
	res, err := pushNode(ctx, cfg, conn, entry, client, coord)
	if err != nil {
		t.Fatalf("pushNode: %v", err)
	}

	if !res.CascadeReapplied {
		t.Error("CascadeReapplied = false, want true")
	}
	// The exit re-received the entry's key as an edge peer, carrying the device's
	// /32 — exactly the state the awg full-replace would have wiped.
	if len(exitFake.addPeer) == 0 {
		t.Fatalf("exit got no edge peer re-applied after push")
	}
	last := exitFake.addPeer[len(exitFake.addPeer)-1]
	if last.GetPublicKey() != entry.WGPublicKey {
		t.Errorf("edge peer key = %q, want entry key %q", last.GetPublicKey(), entry.WGPublicKey)
	}
	wantCIDR := false
	for _, ip := range last.GetAllowedIps() {
		if ip == "10.86.0.5/32" {
			wantCIDR = true
		}
	}
	if !wantCIDR {
		t.Errorf("edge peer allowed-ips = %v, want the device CIDR 10.86.0.5/32", last.GetAllowedIps())
	}
}

// TestPushNodeToleratesXRayUnimplemented proves the second carried-over
// invariant: a node without REALITY support (Unimplemented on the XRay push)
// does not abort the push — XRaySkipped is set and the cascade re-apply still
// runs, so the node's edge peer is never left wiped.
func TestPushNodeToleratesXRayUnimplemented(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	node := mkNode(t, conn, "exit-only", "exit:8444", "3.3.3.3", "EXITONLY=")

	cfg := &config.Config{Posture: config.PostureEnterprise, StateDir: "."}
	cfg.Protocols.XRay = true // force the XRay branch
	cfg.Reality.DecoySite = "www.microsoft.com"

	client := &fakePushClient{appliedRev: 1, xrayUnimpl: true}
	noopCoord := stubReconciler{}
	res, err := pushNode(ctx, cfg, conn, node, client, &noopCoord)
	if err != nil {
		t.Fatalf("pushNode: %v", err)
	}
	if !client.xrayCalled {
		t.Error("XRay push was not attempted")
	}
	if !res.XRaySkipped {
		t.Error("XRaySkipped = false, want true on Unimplemented")
	}
	if !res.CascadeReapplied {
		t.Error("cascade re-apply did not run after a tolerated XRay skip")
	}
	if !noopCoord.called {
		t.Error("ReconcileNode was not called")
	}
}

type stubReconciler struct{ called bool }

func (s *stubReconciler) ReconcileNode(_ context.Context, _ string) error {
	s.called = true
	return nil
}
