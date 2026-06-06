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
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/wg"
)

// fakeNode records every control RPC the coordinator makes to one node.
type fakeNode struct {
	configure  []*nodev1.InnerLinkConfig
	removeLink []string
	addPeer    []*nodev1.Peer
	removePeer []string
	setNet     []*nodev1.NetworkConfig
}

func (f *fakeNode) ConfigureInnerLink(_ context.Context, cfg *nodev1.InnerLinkConfig, rev int64) (*nodev1.ConfigureInnerLinkResponse, error) {
	f.configure = append(f.configure, cfg)
	return &nodev1.ConfigureInnerLinkResponse{AppliedRevision: rev, Reloaded: true}, nil
}
func (f *fakeNode) RemoveInnerLink(_ context.Context, iface string) (*nodev1.RemoveInnerLinkResponse, error) {
	f.removeLink = append(f.removeLink, iface)
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
func (f *fakeNode) SetNetworkConfig(_ context.Context, fwd, masq, iso bool, transits []*nodev1.TransitRoute) (*nodev1.SetNetworkConfigResponse, error) {
	f.setNet = append(f.setNet, &nodev1.NetworkConfig{
		Forwarding: fwd, Masquerade: masq, Isolation: iso, Transits: transits,
	})
	return &nodev1.SetNetworkConfigResponse{Applied: true}, nil
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

func newFleet() *fakeFleet { return &fakeFleet{nodes: map[string]*fakeNode{}} }

// lastNet returns the most recent SetNetworkConfig the node received.
func (f *fakeNode) lastNet() *nodev1.NetworkConfig {
	if f == nil || len(f.setNet) == 0 {
		return nil
	}
	return f.setNet[len(f.setNet)-1]
}

// lastPeer returns the most recent AddPeer the node received.
func (f *fakeNode) lastPeer() *nodev1.Peer {
	if f == nil || len(f.addPeer) == 0 {
		return nil
	}
	return f.addPeer[len(f.addPeer)-1]
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

// validObf is an obfuscation set that satisfies node's structural rules.
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

// mkDeviceOn creates a user+device with a tunnel (peer) on the given node, and
// returns the device id. allowedIP is the device's tunnel address there.
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

// mkSpecOn creates a user+device and a cascade profile spec bound to pathID,
// with the profile's entry peer (tagged with the spec id) on entryNode — the
// per-profile equivalent of mkDeviceOn + a device_exits binding. Returns the
// spec.
func mkSpecOn(t *testing.T, conn *sql.DB, entryNodeID, pathID, email, devPub, allowedIP string) fleet.ProfileSpec {
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
	spec, err := fleet.CreateProfileSpec(ctx, conn, fleet.ProfileSpec{
		UserID: user.ID, DeviceID: dev.ID, Name: "cascade", PathID: pathID, Protocol: fleet.ProtoAmneziaWG,
	})
	if err != nil {
		t.Fatalf("create spec: %v", err)
	}
	if _, err := fleet.CreatePeer(ctx, conn, fleet.Peer{
		NodeID: entryNodeID, DeviceID: dev.ID, Protocol: "amneziawg",
		PublicKey: devPub, AllowedIP: allowedIP, ProfileSpecID: spec.ID,
	}); err != nil {
		t.Fatalf("create spec peer: %v", err)
	}
	return spec
}

func mkPath(t *testing.T, conn *sql.DB, name string, nodeIDs ...string) fleet.Path {
	t.Helper()
	p, err := fleet.CreatePath(context.Background(), conn, name, "", nodeIDs)
	if err != nil {
		t.Fatalf("create path %s: %v", name, err)
	}
	return p
}

// TestProvisionPathConfiguresEachSegmentDialer proves a 3-node path brings up an
// inner-link dialer on the entry (toward the mid) and on the mid (toward the
// exit), each carrying the *target's* obfuscation and public endpoint.
func TestProvisionPathConfiguresEachSegmentDialer(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, mid.ID, exit.ID)
	got, err := coord.ProvisionPath(ctx, p.ID)
	if err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	if got.Status != fleet.StatusActive {
		t.Errorf("path status = %q, want active", got.Status)
	}

	linkEM, _ := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID)
	linkME, _ := fleet.GetNodeLinkByEdge(ctx, conn, mid.ID, exit.ID)

	// Entry dials the mid (mid's pubkey + endpoint :443, mid's obfuscation H1=10).
	en := ff.nodes["entry:8444"]
	if en == nil || len(en.configure) != 1 {
		t.Fatalf("entry should get one ConfigureInnerLink, got %+v", en)
	}
	cfgEM := en.configure[0]
	if cfgEM.GetInterface() != linkEM.InnerInterface || cfgEM.GetExit().GetPublicKey() != "MIDPUB=" {
		t.Errorf("entry→mid dialer mismatch: iface=%s exit=%s", cfgEM.GetInterface(), cfgEM.GetExit().GetPublicKey())
	}
	if eps := cfgEM.GetExit().GetEndpoints(); len(eps) != 1 || eps[0] != "2.2.2.2:443" {
		t.Errorf("entry→mid endpoint = %v, want [2.2.2.2:443]", eps)
	}

	// Mid dials the exit.
	mn := ff.nodes["mid:8444"]
	if mn == nil || len(mn.configure) != 1 {
		t.Fatalf("mid should get one ConfigureInnerLink, got %+v", mn)
	}
	cfgME := mn.configure[0]
	if cfgME.GetInterface() != linkME.InnerInterface || cfgME.GetExit().GetPublicKey() != "EXITPUB=" {
		t.Errorf("mid→exit dialer mismatch: iface=%s exit=%s", cfgME.GetInterface(), cfgME.GetExit().GetPublicKey())
	}
	if cfgME.GetMtu() < 1280 {
		t.Errorf("inner MTU %d below floor", cfgME.GetMtu())
	}
	// The exit terminates the link on its client interface — no dialer of its own.
	if ex := ff.nodes["exit:8444"]; ex != nil && len(ex.configure) != 0 {
		t.Errorf("exit should get no ConfigureInnerLink, got %+v", ex.configure)
	}
}

// TestBindDeviceThreadsPathEntryCIDR is the linchpin: every hop's transit and
// inner-peer AllowedIPs use the device's address ON THE PATH ENTRY — the mid and
// exit have no peer for the device, so a per-segment lookup would fail outright.
func TestBindDeviceThreadsPathEntryCIDR(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	dev := mkDeviceOn(t, conn, entry.ID, "u@x.test", "DEVPUB=", "10.86.0.5")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, mid.ID, exit.ID)
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	if err := coord.BindDeviceToPath(ctx, dev, p.ID); err != nil {
		t.Fatalf("BindDeviceToPath: %v", err)
	}

	linkEM, _ := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID)
	linkME, _ := fleet.GetNodeLinkByEdge(ctx, conn, mid.ID, exit.ID)
	const wantCIDR = "10.86.0.5/32"

	// Mid receives the entry as a peer carrying the device /32.
	if got := ff.nodes["mid:8444"].lastPeer(); got == nil || got.GetPublicKey() != "ENTRYPUB=" ||
		len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != wantCIDR {
		t.Errorf("mid entry-peer = %+v, want pubkey ENTRYPUB= allowed [%s]", got, wantCIDR)
	}
	// Exit receives the mid as a peer carrying the same device /32.
	if got := ff.nodes["exit:8444"].lastPeer(); got == nil || got.GetPublicKey() != "MIDPUB=" ||
		len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != wantCIDR {
		t.Errorf("exit mid-peer = %+v, want pubkey MIDPUB= allowed [%s]", got, wantCIDR)
	}
	// Entry transits the device into the entry→mid link.
	assertSingleTransit(t, "entry", ff.nodes["entry:8444"].lastNet(), wantCIDR, linkEM)
	// Mid transits the device into the mid→exit link (forwarded client, no local peer).
	assertSingleTransit(t, "mid", ff.nodes["mid:8444"].lastNet(), wantCIDR, linkME)
	// Exit has no transit (it is the final hop).
	if got := ff.nodes["exit:8444"].lastNet(); got != nil && len(got.GetTransits()) != 0 {
		t.Errorf("exit should carry no transits, got %+v", got.GetTransits())
	}
}

// TestProfileSpecThreadsPathEntryCIDR proves the per-profile binding: a profile
// spec whose path_id is the path routes its OWN entry tunnel IP (the peer tagged
// with the spec id) through every hop — no device_exits row involved. The
// post-push ReconcileNode is what wires it, exactly as for a device.
func TestProfileSpecThreadsPathEntryCIDR(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, mid.ID, exit.ID)
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	// The spec's path_id is the binding; provisioning placed its entry peer.
	mkSpecOn(t, conn, entry.ID, p.ID, "u@x.test", "DEVPUB=", "10.86.0.7")
	// The post-push reconcile of any path node wires the whole path.
	if err := coord.ReconcileNode(ctx, entry.ID); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}

	linkEM, _ := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID)
	linkME, _ := fleet.GetNodeLinkByEdge(ctx, conn, mid.ID, exit.ID)
	const wantCIDR = "10.86.0.7/32"

	if got := ff.nodes["mid:8444"].lastPeer(); got == nil || got.GetPublicKey() != "ENTRYPUB=" ||
		len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != wantCIDR {
		t.Errorf("mid entry-peer = %+v, want pubkey ENTRYPUB= allowed [%s]", got, wantCIDR)
	}
	if got := ff.nodes["exit:8444"].lastPeer(); got == nil || got.GetPublicKey() != "MIDPUB=" ||
		len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != wantCIDR {
		t.Errorf("exit mid-peer = %+v, want pubkey MIDPUB= allowed [%s]", got, wantCIDR)
	}
	assertSingleTransit(t, "entry", ff.nodes["entry:8444"].lastNet(), wantCIDR, linkEM)
	assertSingleTransit(t, "mid", ff.nodes["mid:8444"].lastNet(), wantCIDR, linkME)
}

func assertSingleTransit(t *testing.T, who string, net *nodev1.NetworkConfig, cidr string, link fleet.NodeLink) {
	t.Helper()
	if net == nil {
		t.Fatalf("%s got no SetNetworkConfig", who)
	}
	if !net.GetForwarding() {
		t.Errorf("%s transit requires forwarding on", who)
	}
	if len(net.GetTransits()) != 1 {
		t.Fatalf("%s transits = %d, want 1 (%+v)", who, len(net.GetTransits()), net.GetTransits())
	}
	tr := net.GetTransits()[0]
	if tr.GetDeviceCidr() != cidr || tr.GetInnerInterface() != link.InnerInterface ||
		tr.GetMark() != uint32(link.Fwmark) || tr.GetTable() != uint32(link.TableID) {
		t.Errorf("%s transit = %+v, want cidr=%s iface=%s mark=%d table=%d",
			who, tr, cidr, link.InnerInterface, link.Fwmark, link.TableID)
	}
}

// TestSharedEdgeUnionsDevices proves two paths that share the entry→mid edge
// accumulate both devices on that edge (the mid's entry-peer AllowedIPs and the
// entry's transit set), while each onward edge carries only its own device.
func TestSharedEdgeUnionsDevices(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exitA := mkNode(t, conn, "exitA", "exitA:8444", "3.3.3.3", "EXITAPUB=")
	exitB := mkNode(t, conn, "exitB", "exitB:8444", "4.4.4.4", "EXITBPUB=")
	d1 := mkDeviceOn(t, conn, entry.ID, "a@x.test", "D1=", "10.86.0.5")
	d2 := mkDeviceOn(t, conn, entry.ID, "b@x.test", "D2=", "10.86.0.6")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	pA := mkPath(t, conn, "A", entry.ID, mid.ID, exitA.ID)
	pB := mkPath(t, conn, "B", entry.ID, mid.ID, exitB.ID)
	for _, p := range []fleet.Path{pA, pB} {
		if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
			t.Fatalf("ProvisionPath %s: %v", p.Name, err)
		}
	}
	if err := coord.BindDeviceToPath(ctx, d1, pA.ID); err != nil {
		t.Fatalf("bind d1→A: %v", err)
	}
	if err := coord.BindDeviceToPath(ctx, d2, pB.ID); err != nil {
		t.Fatalf("bind d2→B: %v", err)
	}

	// The shared entry→mid edge's exit peer (on the mid) carries BOTH /32s.
	midPeer := ff.nodes["mid:8444"].lastPeer()
	if got := cidrSet(midPeer.GetAllowedIps()); !got["10.86.0.5/32"] || !got["10.86.0.6/32"] || len(got) != 2 {
		t.Errorf("mid entry-peer allowed = %v, want both device /32s", midPeer.GetAllowedIps())
	}
	// The entry's transit set carries both devices into the entry→mid link.
	if got := ff.nodes["entry:8444"].lastNet(); len(got.GetTransits()) != 2 {
		t.Errorf("entry transits = %d, want 2 (both devices)", len(got.GetTransits()))
	}
	// Each onward edge carries only its own device.
	if got := ff.nodes["exitA:8444"].lastPeer(); len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != "10.86.0.5/32" {
		t.Errorf("exitA peer allowed = %v, want [10.86.0.5/32]", got.GetAllowedIps())
	}
	if got := ff.nodes["exitB:8444"].lastPeer(); len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != "10.86.0.6/32" {
		t.Errorf("exitB peer allowed = %v, want [10.86.0.6/32]", got.GetAllowedIps())
	}
}

// TestDeprovisionSharedEdgeKeepsSibling proves tearing down one of two paths
// sharing the entry→mid edge removes only the unique onward link, leaving the
// shared inner interface up for the sibling.
func TestDeprovisionSharedEdgeKeepsSibling(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exitA := mkNode(t, conn, "exitA", "exitA:8444", "3.3.3.3", "EXITAPUB=")
	exitB := mkNode(t, conn, "exitB", "exitB:8444", "4.4.4.4", "EXITBPUB=")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	pA := mkPath(t, conn, "A", entry.ID, mid.ID, exitA.ID)
	pB := mkPath(t, conn, "B", entry.ID, mid.ID, exitB.ID)
	for _, p := range []fleet.Path{pA, pB} {
		if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
			t.Fatalf("ProvisionPath %s: %v", p.Name, err)
		}
	}
	linkEM, _ := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID)
	linkMA, _ := fleet.GetNodeLinkByEdge(ctx, conn, mid.ID, exitA.ID)

	if err := coord.DeprovisionPath(ctx, pA.ID); err != nil {
		t.Fatalf("DeprovisionPath A: %v", err)
	}

	// The shared entry→mid inner iface on the entry must NOT be removed.
	for _, iface := range ff.nodes["entry:8444"].removeLink {
		if iface == linkEM.InnerInterface {
			t.Errorf("shared entry→mid iface %s wrongly removed", iface)
		}
	}
	if _, err := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID); err != nil {
		t.Errorf("shared entry→mid link should survive, got %v", err)
	}
	// The mid→exitA iface (only A used it) must be removed and the row deleted.
	found := false
	for _, iface := range ff.nodes["mid:8444"].removeLink {
		if iface == linkMA.InnerInterface {
			found = true
		}
	}
	if !found {
		t.Errorf("mid→exitA iface %s should be removed, got %v", linkMA.InnerInterface, ff.nodes["mid:8444"].removeLink)
	}
	if _, err := fleet.GetNodeLink(ctx, conn, linkMA.ID); err == nil {
		t.Error("mid→exitA link row should be deleted")
	}
	// Path B and its onward edge survive.
	if _, err := fleet.GetPath(ctx, conn, pB.ID); err != nil {
		t.Errorf("path B should survive: %v", err)
	}
}

// TestDeprovisionPathTearsDownAndUnbinds covers the single-path teardown.
func TestDeprovisionPathTearsDownAndUnbinds(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	mid := mkNode(t, conn, "mid", "mid:8444", "2.2.2.2", "MIDPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	dev := mkDeviceOn(t, conn, entry.ID, "u@x.test", "DEVPUB=", "10.86.0.5")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, mid.ID, exit.ID)
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	if err := coord.BindDeviceToPath(ctx, dev, p.ID); err != nil {
		t.Fatalf("BindDeviceToPath: %v", err)
	}
	linkEM, _ := fleet.GetNodeLinkByEdge(ctx, conn, entry.ID, mid.ID)
	linkME, _ := fleet.GetNodeLinkByEdge(ctx, conn, mid.ID, exit.ID)

	if err := coord.DeprovisionPath(ctx, p.ID); err != nil {
		t.Fatalf("DeprovisionPath: %v", err)
	}
	if !contains(ff.nodes["entry:8444"].removeLink, linkEM.InnerInterface) {
		t.Errorf("entry should RemoveInnerLink(%s), got %v", linkEM.InnerInterface, ff.nodes["entry:8444"].removeLink)
	}
	if !contains(ff.nodes["mid:8444"].removeLink, linkME.InnerInterface) {
		t.Errorf("mid should RemoveInnerLink(%s), got %v", linkME.InnerInterface, ff.nodes["mid:8444"].removeLink)
	}
	if _, err := fleet.GetPath(ctx, conn, p.ID); err == nil {
		t.Error("path should be deleted")
	}
	if _, err := fleet.GetDeviceExit(ctx, conn, dev); err == nil {
		t.Error("device binding should be cleared on deprovision")
	}
}

// TestBindRequiresTunnelOnEntry rejects binding a device with no peer on the
// path entry — its profile would have nowhere to enter the chain.
func TestBindRequiresTunnelOnEntry(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	// Device has a tunnel on the EXIT, not the entry.
	dev := mkDeviceOn(t, conn, exit.ID, "u@x.test", "DEVPUB=", "10.86.0.9")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, exit.ID)
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	if err := coord.BindDeviceToPath(ctx, dev, p.ID); err == nil {
		t.Error("binding a device without a tunnel on the path entry should fail")
	}
}

// TestReconcileNodeReappliesEdgePeer guards bug #3: a `cox nodes push` device-
// peer full-replace wipes an exit's cascade edge peer (the entry's key carrying
// the device IPs); ReconcileNode — called right after the push — must re-add it,
// or multi-hop egress black-holes. A node in no path is a no-op.
func TestReconcileNodeReappliesEdgePeer(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	entry := mkNode(t, conn, "entry", "entry:8444", "1.1.1.1", "ENTRYPUB=")
	exit := mkNode(t, conn, "exit", "exit:8444", "3.3.3.3", "EXITPUB=")
	dev := mkDeviceOn(t, conn, entry.ID, "u@x.test", "DEVPUB=", "10.86.0.5")
	ff := newFleet()
	coord := cascade.New(conn, ff.dial)

	p := mkPath(t, conn, "p", entry.ID, exit.ID)
	if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
		t.Fatalf("ProvisionPath: %v", err)
	}
	if err := coord.BindDeviceToPath(ctx, dev, p.ID); err != nil {
		t.Fatalf("BindDeviceToPath: %v", err)
	}

	before := len(ff.nodes["exit:8444"].addPeer)
	if before == 0 {
		t.Fatal("setup: exit never received its edge peer")
	}

	// Simulate the post-device-push reconcile.
	if err := coord.ReconcileNode(ctx, exit.ID); err != nil {
		t.Fatalf("ReconcileNode: %v", err)
	}
	if len(ff.nodes["exit:8444"].addPeer) <= before {
		t.Fatal("ReconcileNode did not re-issue the exit's edge peer")
	}
	if got := ff.nodes["exit:8444"].lastPeer(); got == nil || got.GetPublicKey() != "ENTRYPUB=" ||
		len(got.GetAllowedIps()) != 1 || got.GetAllowedIps()[0] != "10.86.0.5/32" {
		t.Errorf("re-applied edge peer = %+v, want ENTRYPUB= allowed [10.86.0.5/32]", got)
	}

	// A node in no path: no error, no RPCs.
	lone := mkNode(t, conn, "lone", "lone:8444", "9.9.9.9", "LONEPUB=")
	if err := coord.ReconcileNode(ctx, lone.ID); err != nil {
		t.Fatalf("ReconcileNode(no-path): %v", err)
	}
	if ff.nodes["lone:8444"] != nil {
		t.Error("ReconcileNode on a path-less node should make no calls")
	}
}

func cidrSet(cidrs []string) map[string]bool {
	m := make(map[string]bool, len(cidrs))
	for _, c := range cidrs {
		m[c] = true
	}
	return m
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
