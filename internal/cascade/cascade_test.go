// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cascade_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/cascade"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"github.com/PharosVPN/coxswain/internal/wg"
)

// fakeNode records every control RPC the coordinator makes to one node.
type fakeNode struct {
	configure  []*buoyv1.InnerLinkConfig
	removeLink []string
	addPeer    []*buoyv1.Peer
	removePeer []string
	setNet     []*buoyv1.NetworkConfig
}

func (f *fakeNode) ConfigureInnerLink(_ context.Context, cfg *buoyv1.InnerLinkConfig, rev int64) (*buoyv1.ConfigureInnerLinkResponse, error) {
	f.configure = append(f.configure, cfg)
	return &buoyv1.ConfigureInnerLinkResponse{AppliedRevision: rev, Reloaded: true}, nil
}
func (f *fakeNode) RemoveInnerLink(_ context.Context, iface string) (*buoyv1.RemoveInnerLinkResponse, error) {
	f.removeLink = append(f.removeLink, iface)
	return &buoyv1.RemoveInnerLinkResponse{Removed: true}, nil
}
func (f *fakeNode) AddPeer(_ context.Context, p *buoyv1.Peer) (*buoyv1.PeerResponse, error) {
	f.addPeer = append(f.addPeer, p)
	return &buoyv1.PeerResponse{Applied: true}, nil
}
func (f *fakeNode) RemovePeer(_ context.Context, _ buoyv1.Protocol, pub string) (*buoyv1.PeerResponse, error) {
	f.removePeer = append(f.removePeer, pub)
	return &buoyv1.PeerResponse{Applied: true}, nil
}
func (f *fakeNode) SetNetworkConfig(_ context.Context, fwd, masq, iso bool, transits []*buoyv1.TransitRoute) (*buoyv1.SetNetworkConfigResponse, error) {
	f.setNet = append(f.setNet, &buoyv1.NetworkConfig{
		Forwarding: fwd, Masquerade: masq, Isolation: iso, Transits: transits,
	})
	return &buoyv1.SetNetworkConfigResponse{Applied: true}, nil
}
func (f *fakeNode) Close() error { return nil }

type fakeFleet struct{ nodes map[string]*fakeNode }

func (f *fakeFleet) dial(addr string) (cascade.NodeClient, error) {
	n, ok := f.nodes[addr]
	if !ok {
		n = &fakeNode{}
		f.nodes[addr] = n
	}
	return n, nil
}

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return conn
}

// validObf is an obfuscation set that satisfies buoy's structural rules.
func validObf() wg.Obfuscation {
	return wg.Obfuscation{Jc: 5, Jmin: 25, Jmax: 800, S1: 20, S2: 30, S3: 40, S4: 50, H1: 10, H2: 11, H3: 12, H4: 13}
}

// seed builds an entry node, an exit node, and a device with a tunnel on the
// entry; it returns ids and the fake fleet.
func seed(t *testing.T, conn *sql.DB) (entry, exit fleet.Node, deviceID string, ff *fakeFleet) {
	t.Helper()
	ctx := context.Background()
	var err error
	entry, err = fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "entry", Region: "eu", ControlAddr: "entry:8444", PublicIP: "1.1.1.1",
		WGPublicKey: "ENTRYPUB=", Obfuscation: validObf(),
	})
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	exit, err = fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "exit", Region: "us", ControlAddr: "exit:8444", PublicIP: "2.2.2.2",
		EndpointIPs: []string{"2.2.2.2"}, WGPublicKey: "EXITPUB=", Obfuscation: validObf(),
	})
	if err != nil {
		t.Fatalf("create exit: %v", err)
	}
	user, err := account.CreateUser(ctx, conn, account.User{Email: "u@example.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "phone"})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: entry.ID, DeviceID: dev.ID, Protocol: "amneziawg",
		PublicKey: "DEVPUB=", AllowedIP: "10.86.0.5",
	}); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	return entry, exit, dev.ID, &fakeFleet{nodes: map[string]*fakeNode{}}
}

func TestProvisionLinkConfiguresEntry(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exit, _, ff := seed(t, conn)
	coord := cascade.New(conn, ff.dial)

	link, err := coord.ProvisionLink(ctx, entry.ID, exit.ID)
	if err != nil {
		t.Fatalf("ProvisionLink: %v", err)
	}
	if link.Status != "active" {
		t.Errorf("link status = %q, want active", link.Status)
	}
	en := ff.nodes["entry:8444"]
	if en == nil || len(en.configure) != 1 {
		t.Fatalf("entry should get one ConfigureInnerLink, got %+v", en)
	}
	cfg := en.configure[0]
	if cfg.GetInterface() != link.InnerInterface || cfg.GetListenPort() != uint32(link.ListenPort) {
		t.Errorf("inner cfg iface/port mismatch: %+v vs link %+v", cfg, link)
	}
	if cfg.GetMtu() < 1280 {
		t.Errorf("inner MTU %d below floor", cfg.GetMtu())
	}
	if cfg.GetPeerObfuscation().GetH1() != 10 {
		t.Errorf("inner cfg should carry the EXIT obfuscation (H1=10), got %d", cfg.GetPeerObfuscation().GetH1())
	}
	ex := cfg.GetExit()
	if ex.GetPublicKey() != "EXITPUB=" || len(ex.GetEndpoints()) != 1 || ex.GetEndpoints()[0] != "2.2.2.2:443" {
		t.Errorf("exit peer mismatch: %+v", ex)
	}
	if len(ex.GetAllowedIps()) != 1 || ex.GetAllowedIps()[0] != "0.0.0.0/0" || ex.GetPresharedKey() == "" {
		t.Errorf("exit peer allowed-ips/psk mismatch: %+v", ex)
	}
}

func TestBindExitWiresBothEnds(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exit, deviceID, ff := seed(t, conn)
	coord := cascade.New(conn, ff.dial)

	link, err := coord.ProvisionLink(ctx, entry.ID, exit.ID)
	if err != nil {
		t.Fatalf("ProvisionLink: %v", err)
	}
	if err := coord.BindExit(ctx, deviceID, entry.ID, exit.ID); err != nil {
		t.Fatalf("BindExit: %v", err)
	}

	// Exit: the entry peer carries the device's /32 + the link PSK.
	ex := ff.nodes["exit:8444"]
	if ex == nil || len(ex.addPeer) == 0 {
		t.Fatalf("exit should get an AddPeer, got %+v", ex)
	}
	last := ex.addPeer[len(ex.addPeer)-1]
	if last.GetPublicKey() != "ENTRYPUB=" {
		t.Errorf("exit entry-peer pubkey = %q, want ENTRYPUB=", last.GetPublicKey())
	}
	if len(last.GetAllowedIps()) != 1 || last.GetAllowedIps()[0] != "10.86.0.5/32" {
		t.Errorf("exit entry-peer allowed-ips = %v, want [10.86.0.5/32]", last.GetAllowedIps())
	}
	if last.GetPresharedKey() == "" {
		t.Error("exit entry-peer missing PSK")
	}

	// Entry: a transit route for the device into the inner interface.
	en := ff.nodes["entry:8444"]
	if len(en.setNet) == 0 {
		t.Fatalf("entry should get a SetNetworkConfig")
	}
	net := en.setNet[len(en.setNet)-1]
	if !net.GetForwarding() {
		t.Error("entry transit requires forwarding on")
	}
	if len(net.GetTransits()) != 1 {
		t.Fatalf("entry transits = %d, want 1", len(net.GetTransits()))
	}
	tr := net.GetTransits()[0]
	if tr.GetDeviceCidr() != "10.86.0.5/32" || tr.GetInnerInterface() != link.InnerInterface ||
		tr.GetMark() != uint32(link.Fwmark) || tr.GetTable() != uint32(link.TableID) {
		t.Errorf("transit route mismatch: %+v vs link %+v", tr, link)
	}
}

func TestExitSwitchReconcilesOldAndNew(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exitA, deviceID, ff := seed(t, conn)
	// A second exit + link from the same entry.
	exitB, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "exit-b", Region: "asia", ControlAddr: "exitb:8444", PublicIP: "3.3.3.3",
		EndpointIPs: []string{"3.3.3.3"}, WGPublicKey: "EXITBPUB=", Obfuscation: validObf(),
	})
	if err != nil {
		t.Fatalf("create exit-b: %v", err)
	}
	coord := cascade.New(conn, ff.dial)
	if _, err := coord.ProvisionLink(ctx, entry.ID, exitA.ID); err != nil {
		t.Fatalf("ProvisionLink A: %v", err)
	}
	linkB, err := coord.ProvisionLink(ctx, entry.ID, exitB.ID)
	if err != nil {
		t.Fatalf("ProvisionLink B: %v", err)
	}

	if err := coord.BindExit(ctx, deviceID, entry.ID, exitA.ID); err != nil {
		t.Fatalf("BindExit A: %v", err)
	}
	// Switch to exit B.
	if err := coord.BindExit(ctx, deviceID, entry.ID, exitB.ID); err != nil {
		t.Fatalf("BindExit B (switch): %v", err)
	}

	// Old exit (A) had its entry peer removed (now zero devices on that link).
	exA := ff.nodes["exit:8444"]
	if len(exA.removePeer) == 0 {
		t.Errorf("old exit should have its entry peer removed on switch")
	}
	// New exit (B) got the device's /32.
	exB := ff.nodes["exitb:8444"]
	if len(exB.addPeer) == 0 || exB.addPeer[len(exB.addPeer)-1].GetAllowedIps()[0] != "10.86.0.5/32" {
		t.Errorf("new exit should carry the device /32, got %+v", exB.addPeer)
	}
	// Entry's final transit set points at exit B's interface.
	en := ff.nodes["entry:8444"]
	final := en.setNet[len(en.setNet)-1]
	if len(final.GetTransits()) != 1 || final.GetTransits()[0].GetInnerInterface() != linkB.InnerInterface {
		t.Errorf("entry transit should point at link B (%s), got %+v", linkB.InnerInterface, final.GetTransits())
	}
}

func TestClearExitRemovesRouting(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exit, deviceID, ff := seed(t, conn)
	coord := cascade.New(conn, ff.dial)
	if _, err := coord.ProvisionLink(ctx, entry.ID, exit.ID); err != nil {
		t.Fatalf("ProvisionLink: %v", err)
	}
	if err := coord.BindExit(ctx, deviceID, entry.ID, exit.ID); err != nil {
		t.Fatalf("BindExit: %v", err)
	}
	if err := coord.ClearExit(ctx, deviceID); err != nil {
		t.Fatalf("ClearExit: %v", err)
	}
	// Exit entry-peer removed; entry transit set now empty.
	ex := ff.nodes["exit:8444"]
	if len(ex.removePeer) == 0 {
		t.Error("clearing should remove the exit's entry peer")
	}
	en := ff.nodes["entry:8444"]
	if got := en.setNet[len(en.setNet)-1].GetTransits(); len(got) != 0 {
		t.Errorf("entry transits should be empty after clear, got %+v", got)
	}
}

func TestBindExitRequiresLink(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exit, deviceID, ff := seed(t, conn)
	coord := cascade.New(conn, ff.dial)
	// No ProvisionLink — binding must fail with a helpful error.
	if err := coord.BindExit(ctx, deviceID, entry.ID, exit.ID); err == nil {
		t.Error("BindExit without a link should error")
	}
}

func TestDeprovisionLinkTearsDown(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry, exit, deviceID, ff := seed(t, conn)
	coord := cascade.New(conn, ff.dial)
	link, err := coord.ProvisionLink(ctx, entry.ID, exit.ID)
	if err != nil {
		t.Fatalf("ProvisionLink: %v", err)
	}
	if err := coord.BindExit(ctx, deviceID, entry.ID, exit.ID); err != nil {
		t.Fatalf("BindExit: %v", err)
	}
	if err := coord.DeprovisionLink(ctx, link.ID); err != nil {
		t.Fatalf("DeprovisionLink: %v", err)
	}
	en := ff.nodes["entry:8444"]
	if len(en.removeLink) == 0 || en.removeLink[len(en.removeLink)-1] != link.InnerInterface {
		t.Errorf("entry should get RemoveInnerLink(%s), got %v", link.InnerInterface, en.removeLink)
	}
	// The row and the device binding are gone.
	if _, err := fleet.GetNodeLink(ctx, conn, link.ID); err == nil {
		t.Error("node link should be deleted")
	}
	if _, err := fleet.GetDeviceExit(ctx, conn, deviceID); err == nil {
		t.Error("device binding should be cleared on deprovision")
	}
}
