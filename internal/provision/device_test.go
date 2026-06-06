// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package provision_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"github.com/PharosVPN/coxswain/internal/wg"
)

var opts = provision.Options{
	VPNSubnet: "10.86.0.0/16",
	PortMin:   2000,
	PortMax:   60000,
	Rotation:  profile.RotationPolicy{Enabled: true, IntervalSeconds: 600, JitterSeconds: 120},
}

// testObfuscation is a non-zero obfuscation set marking a node as data-plane
// ready (its H1-H4 are non-zero, so it passes provisioning's readiness gate).
var testObfuscation = wg.Obfuscation{
	Jc: 4, Jmin: 40, Jmax: 70,
	S1: 30, S2: 45, S3: 60, S4: 75,
	H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755,
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

// enrolledUser creates a user with an E2E encryption key and returns the user
// ID and the keypair (for decrypting the issued profile).
func enrolledUser(t *testing.T, conn *sql.DB) (string, e2e.KeyPair) {
	t.Helper()
	ctx := context.Background()
	u, err := account.CreateUser(ctx, conn, account.User{Email: "u@example.com"})
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
	if err := account.SetEncryptionKey(ctx, conn, u.ID, kp.Public, wrapped); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	return u.ID, kp
}

// decryptProfile opens the latest sealed profile for a device and returns the
// decoded Profile.
func decryptProfile(t *testing.T, ctx context.Context, conn *sql.DB, userID, deviceID string, kp e2e.KeyPair) profile.Profile {
	t.Helper()
	ciphertext, _, err := profile.LatestCiphertext(ctx, conn, userID, deviceID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(ciphertext, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	plaintext, err := e2e.Open(bundle, kp.Private, signing.Public)
	if err != nil {
		t.Fatalf("e2e.Open: %v", err)
	}
	var prof profile.Profile
	if err := json.Unmarshal(plaintext, &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	return prof
}

func TestProvisionDevice(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, kp := enrolledUser(t, conn)

	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "phone"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// Two ready nodes and one still pending (no WG key) — the pending one
	// must be skipped.
	for _, n := range []fleet.Node{
		{Name: "ams-1", Region: "eu", PublicIP: "203.0.113.7", WGPublicKey: "bm9kZS1hbXMtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation},
		{Name: "fra-1", Region: "eu", PublicIP: "203.0.113.8", WGPublicKey: "bm9kZS1mcmEtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation},
		{Name: "pending", Region: "us"},
	} {
		if _, err := fleet.CreateNode(ctx, conn, n); err != nil {
			t.Fatalf("CreateNode %s: %v", n.Name, err)
		}
	}

	res, err := provision.ProvisionDevice(ctx, conn, device.ID, opts)
	if err != nil {
		t.Fatalf("ProvisionDevice: %v", err)
	}
	if res.PeerCount != 2 {
		t.Errorf("peer count: got %d want 2 (pending node should be skipped)", res.PeerCount)
	}
	if !strings.HasPrefix(res.TunnelIP, "10.86.") {
		t.Errorf("tunnel IP %q not in subnet", res.TunnelIP)
	}

	peers, err := fleet.ListPeersByDevice(ctx, conn, device.ID)
	if err != nil {
		t.Fatalf("ListPeersByDevice: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("recorded peers: got %d want 2", len(peers))
	}
	for _, p := range peers {
		if p.PresharedKey == "" || p.PublicKey == "" || p.AllowedIP != res.TunnelIP {
			t.Errorf("peer not fully provisioned: %+v", p)
		}
	}

	// The issued profile decrypts to a populated profile (now per-device).
	ciphertext, _, err := profile.LatestCiphertext(ctx, conn, userID, device.ID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(ciphertext, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	plaintext, err := e2e.Open(bundle, kp.Private, signing.Public)
	if err != nil {
		t.Fatalf("e2e.Open: %v", err)
	}
	var prof profile.Profile
	if err := json.Unmarshal(plaintext, &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if len(prof.Nodes) != 2 {
		t.Fatalf("profile nodes: got %d want 2", len(prof.Nodes))
	}
	proto := prof.Nodes[0].Protocols[0]
	if proto.Type != profile.ProtocolAmneziaWG {
		t.Errorf("protocol type: got %q", proto.Type)
	}
	// The amneziawg params carry the device key, the endpoint pool, and the
	// rotation policy (decision 17).
	var params struct {
		PrivateKey  string                 `json:"private_key"`
		PublicKey   string                 `json:"public_key"`
		Endpoints   []profile.EndpointPool `json:"endpoints"`
		Rotation    profile.RotationPolicy `json:"rotation"`
		Obfuscation wg.Obfuscation         `json:"obfuscation"`
	}
	if err := json.Unmarshal(proto.Params, &params); err != nil {
		t.Fatalf("unmarshal params: %v", err)
	}
	if params.PrivateKey == "" || params.PublicKey == "" {
		t.Errorf("amneziawg params incomplete: %+v", params)
	}
	// The node's obfuscation set is carried into the profile so the client can
	// build a tunnel that handshakes (DESIGN §3).
	if params.Obfuscation != testObfuscation {
		t.Errorf("obfuscation not carried into params: got %+v want %+v", params.Obfuscation, testObfuscation)
	}
	// The pool advertises the node's real client listen port (443), not a range —
	// the client must dial a port the node is actually bound to.
	if len(params.Endpoints) != 1 || params.Endpoints[0].PortMin != profile.ClientListenPort || params.Endpoints[0].PortMax != profile.ClientListenPort {
		t.Errorf("endpoint pool: got %+v want port %d", params.Endpoints, profile.ClientListenPort)
	}
	if !params.Rotation.Enabled || params.Rotation.IntervalSeconds != 600 {
		t.Errorf("rotation policy not carried: %+v", params.Rotation)
	}
}

// TestProvisionDeviceIdempotent guards that re-provisioning a device keeps its
// tunnel IP and does not accumulate stale peers — a churned IP orphans the
// device's cascade fwmark (the live-test regression), and stale peers pile up on
// every node.
func TestProvisionDeviceIdempotent(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, _ := enrolledUser(t, conn)

	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "phone"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	for _, n := range []fleet.Node{
		{Name: "ams-1", Region: "eu", PublicIP: "203.0.113.7", WGPublicKey: "bm9kZS1hbXMtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation},
		{Name: "fra-1", Region: "eu", PublicIP: "203.0.113.8", WGPublicKey: "bm9kZS1mcmEtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation},
	} {
		if _, err := fleet.CreateNode(ctx, conn, n); err != nil {
			t.Fatalf("CreateNode %s: %v", n.Name, err)
		}
	}

	first, err := provision.ProvisionDevice(ctx, conn, device.ID, opts)
	if err != nil {
		t.Fatalf("provision 1: %v", err)
	}
	second, err := provision.ProvisionDevice(ctx, conn, device.ID, opts)
	if err != nil {
		t.Fatalf("provision 2: %v", err)
	}

	if second.TunnelIP != first.TunnelIP {
		t.Errorf("re-provision churned the tunnel IP: %q -> %q", first.TunnelIP, second.TunnelIP)
	}
	peers, err := fleet.ListPeersByDevice(ctx, conn, device.ID)
	if err != nil {
		t.Fatalf("ListPeersByDevice: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("stale peers accumulated across re-provision: got %d want 2", len(peers))
	}
	for _, p := range peers {
		if p.AllowedIP != first.TunnelIP {
			t.Errorf("peer IP drifted from the device's allocation: got %q want %q", p.AllowedIP, first.TunnelIP)
		}
	}
}

// TestProvisionDeviceXRay checks that with XRay enabled, a device gets both an
// AmneziaWG peer and an XRay/REALITY peer on a node that reported both
// identities — the XRay peer carrying a VLESS UUID (shared with the node's
// other XRay peers), the flow, and no PSK — and that the sealed profile carries
// an xray-reality protocol entry.
func TestProvisionDeviceXRay(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, kp := enrolledUser(t, conn)

	device, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "phone"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// Two nodes report both data planes; one reports AmneziaWG only.
	for _, n := range []fleet.Node{
		{Name: "ams-1", Region: "eu", PublicIP: "203.0.113.7", WGPublicKey: "bm9kZS1hbXMtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation, XRayPublicKey: "reality-pub-ams"},
		{Name: "fra-1", Region: "eu", PublicIP: "203.0.113.8", WGPublicKey: "bm9kZS1mcmEtd2cta2V5LWJhc2U2NA==", Obfuscation: testObfuscation, XRayPublicKey: "reality-pub-fra"},
		{Name: "wg-only", Region: "us", PublicIP: "203.0.113.9", WGPublicKey: "d2ctb25seS1ub2RlLWtleS1iYXNlNjQteA==", Obfuscation: testObfuscation},
	} {
		if _, err := fleet.CreateNode(ctx, conn, n); err != nil {
			t.Fatalf("CreateNode %s: %v", n.Name, err)
		}
	}

	xrayOpts := opts
	xrayOpts.XRay = provision.XRayOptions{Enabled: true, ServerName: "www.microsoft.com"}

	if _, err := provision.ProvisionDevice(ctx, conn, device.ID, xrayOpts); err != nil {
		t.Fatalf("ProvisionDevice: %v", err)
	}

	peers, err := fleet.ListPeersByDevice(ctx, conn, device.ID)
	if err != nil {
		t.Fatalf("ListPeersByDevice: %v", err)
	}
	// 3 AmneziaWG (all nodes) + 2 XRay (the two REALITY-ready nodes).
	var awg, xray int
	var xrayUUIDs = map[string]bool{}
	for _, p := range peers {
		switch p.Protocol {
		case profile.ProtocolAmneziaWG:
			awg++
		case profile.ProtocolXRayReality:
			xray++
			if p.PresharedKey != "" {
				t.Errorf("xray peer should have no PSK: %+v", p)
			}
			if p.Flow != profile.DefaultXRayFlow || p.PublicKey == "" {
				t.Errorf("xray peer missing flow/uuid: %+v", p)
			}
			xrayUUIDs[p.PublicKey] = true
		default:
			t.Errorf("unexpected peer protocol %q", p.Protocol)
		}
	}
	if awg != 3 || xray != 2 {
		t.Fatalf("peers: amneziawg=%d xray=%d, want 3 and 2", awg, xray)
	}
	if len(xrayUUIDs) != 1 {
		t.Fatalf("xray peers should share one device UUID, got %d distinct", len(xrayUUIDs))
	}

	// The sealed profile carries an xray-reality entry on a REALITY-ready node.
	prof := decryptProfile(t, ctx, conn, userID, device.ID, kp)
	foundXRay := false
	for _, n := range prof.Nodes {
		for _, pr := range n.Protocols {
			if pr.Type == profile.ProtocolXRayReality {
				foundXRay = true
			}
		}
	}
	if !foundXRay {
		t.Fatal("profile carries no xray-reality protocol entry")
	}
}

func TestAllocateDeviceIPSequential(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, _ := enrolledUser(t, conn)

	if _, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "n1", Region: "eu", PublicIP: "203.0.113.7", WGPublicKey: "d2cta2V5LWZvci10aGUtdGVzdC1ub2Rl",
		Obfuscation: testObfuscation,
	}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	var ips []string
	for i := 0; i < 3; i++ {
		d, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "d"})
		if err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}
		res, err := provision.ProvisionDevice(ctx, conn, d.ID, opts)
		if err != nil {
			t.Fatalf("ProvisionDevice: %v", err)
		}
		ips = append(ips, res.TunnelIP)
	}
	// Distinct, ascending allocations.
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			t.Fatalf("duplicate tunnel IP %q in %v", ip, ips)
		}
		seen[ip] = true
	}
}
