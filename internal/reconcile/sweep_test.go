// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package reconcile

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
)

// awgService builds an AmneziaWG ServiceStatus for the decision table.
func awgService(peers, handshaking uint32) *nodev1.ServiceStatus {
	return &nodev1.ServiceStatus{
		Protocol:         nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		Running:          true,
		Listening:        true,
		PeerCount:        peers,
		HandshakingPeers: handshaking,
	}
}

// mkStatus builds a GetStatusResponse with an applied revision and an optional
// AmneziaWG service.
func mkStatus(applied int64, svc *nodev1.ServiceStatus) *nodev1.GetStatusResponse {
	r := &nodev1.GetStatusResponse{AppliedRevision: applied}
	if svc != nil {
		r.Services = []*nodev1.ServiceStatus{svc}
	}
	return r
}

// TestNeedsReconcile is the sweep's decision logic, table-driven: it isolates the
// pure heal/no-heal call so the core Option-B behaviour is verified without a
// live node.
func TestNeedsReconcile(t *testing.T) {
	tests := []struct {
		name        string
		status      *nodev1.GetStatusResponse
		intendedRev int64
		wantPush    bool
		wantReason  string // substring; "" means no reason expected
	}{
		{
			name:        "applied behind intended -> push (DRIFT)",
			status:      mkStatus(3, awgService(2, 2)),
			intendedRev: 5,
			wantPush:    true,
			wantReason:  "DRIFT",
		},
		{
			name:        "peers but zero handshaking -> push (STALE)",
			status:      mkStatus(5, awgService(4, 0)),
			intendedRev: 5,
			wantPush:    true,
			wantReason:  "STALE",
		},
		{
			name:        "in sync and handshaking -> no push",
			status:      mkStatus(5, awgService(3, 3)),
			intendedRev: 5,
			wantPush:    false,
		},
		{
			name:        "in sync, some handshaking -> no push",
			status:      mkStatus(5, awgService(4, 1)),
			intendedRev: 5,
			wantPush:    false,
		},
		{
			name:        "in sync, no peers configured -> no push",
			status:      mkStatus(5, awgService(0, 0)),
			intendedRev: 5,
			wantPush:    false,
		},
		{
			name:        "DRIFT takes priority even when handshaking",
			status:      mkStatus(2, awgService(3, 3)),
			intendedRev: 9,
			wantPush:    true,
			wantReason:  "DRIFT",
		},
		{
			name:        "no AmneziaWG service, in sync -> no push",
			status:      mkStatus(5, nil),
			intendedRev: 5,
			wantPush:    false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			push, _, reason := needsReconcile(tc.status, tc.intendedRev)
			if push != tc.wantPush {
				t.Errorf("needsReconcile push = %v, want %v (reason %q)", push, tc.wantPush, reason)
			}
			if tc.wantReason != "" && !strings.Contains(reason, tc.wantReason) {
				t.Errorf("needsReconcile reason = %q, want substring %q", reason, tc.wantReason)
			}
			if !tc.wantPush && reason != "" {
				t.Errorf("needsReconcile reason = %q, want empty for no-push", reason)
			}
		})
	}
}

func TestShouldHeal(t *testing.T) {
	now := time.Now()
	healed := map[string]time.Time{"n": now.Add(-1 * time.Minute)} // healed 1m ago

	if !shouldHeal(false, "n", healed, now, staleHealCooldown) {
		t.Error("DRIFT should always heal, even within the cooldown")
	}
	if shouldHeal(true, "n", healed, now, staleHealCooldown) {
		t.Error("STALE within cooldown should be skipped (idle node, do not re-push)")
	}
	if !shouldHeal(true, "n", healed, now.Add(10*time.Minute), staleHealCooldown) {
		t.Error("STALE past the cooldown should heal again")
	}
	if !shouldHeal(true, "never-healed", healed, now, staleHealCooldown) {
		t.Error("STALE for a node never healed should heal")
	}
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

// TestSweepOnceMarksUnreachable proves the sweep's dial-failure branch: a node
// with a control address that never answers is set to StatusUnreachable (the
// constant that existed but was never wired before Phase 2), and the sweep keeps
// going — one node's silence does not stall the pass. The unreachable node is on
// a closed loopback port so the dial fails fast.
func TestSweepOnceMarksUnreachable(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	// 127.0.0.1:1 is reserved/closed, so the control dial fails quickly.
	bad, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "dead", Region: "eu", ControlAddr: "127.0.0.1:1", PublicIP: "203.0.113.9",
		Status: fleet.StatusActive,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	// A node with no control address is simply skipped (still enrolling).
	if _, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "enrolling", Region: "us", Status: fleet.StatusEnrolling,
	}); err != nil {
		t.Fatalf("CreateNode enrolling: %v", err)
	}

	cfg := &config.Config{Posture: config.PosturePersonal, StateDir: "."}
	healed := SweepOnce(ctx, cfg, conn, nil, nil)
	if healed != 0 {
		t.Errorf("healed = %d, want 0 (the node never answered)", healed)
	}

	got, err := fleet.GetNode(ctx, conn, bad.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.Status != fleet.StatusUnreachable {
		t.Errorf("unreachable node status = %q, want %q", got.Status, fleet.StatusUnreachable)
	}
}

// TestRecordNodeIdentity covers gap #2: the sweep auto-records a node's reported
// AmneziaWG + XRay identity (so a fresh node becomes provisionable with no manual
// `cox nodes status`), and is idempotent — an unchanged identity does not churn
// the node's version on every pass.
func TestRecordNodeIdentity(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)

	// A freshly-onboarded node that has not yet reported its data-plane identity.
	node, err := fleet.CreateNode(ctx, conn, fleet.Node{
		Name: "fresh", Region: "r", ControlAddr: "203.0.113.5:8444", PublicIP: "203.0.113.5",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if node.WGPublicKey != "" || !node.Obfuscation.IsZero() {
		t.Fatalf("setup: node should start with no identity, got %q / %+v", node.WGPublicKey, node.Obfuscation)
	}

	obf := validObf()
	st := &nodev1.GetStatusResponse{
		Amneziawg: &nodev1.AmneziaWGInfo{
			PublicKey:   "NODEWGPUB=",
			Obfuscation: control.AmneziaWGToProto(obf),
		},
		Xray: &nodev1.XRayRealityInfo{PublicKey: "NODEXRAYPUB="},
	}

	recordNodeIdentity(ctx, conn, node, st, nil)

	got, err := fleet.GetNode(ctx, conn, node.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.WGPublicKey != "NODEWGPUB=" {
		t.Errorf("wg public key = %q, want NODEWGPUB=", got.WGPublicKey)
	}
	if got.Obfuscation != obf {
		t.Errorf("obfuscation = %+v, want %+v", got.Obfuscation, obf)
	}
	if got.XRayPublicKey != "NODEXRAYPUB=" {
		t.Errorf("xray public key = %q, want NODEXRAYPUB=", got.XRayPublicKey)
	}
	// The node is now provisionable (the readiness predicate, provision/device.go).
	if got.WGPublicKey == "" || got.Obfuscation.IsZero() {
		t.Error("node should be AmneziaWG-ready after identity recording")
	}

	// Idempotency: recording the SAME identity again must not bump the version.
	versionBefore := got.Version
	recordNodeIdentity(ctx, conn, got, st, nil)
	again, err := fleet.GetNode(ctx, conn, node.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if again.Version != versionBefore {
		t.Errorf("unchanged identity churned version: %d -> %d", versionBefore, again.Version)
	}

	// A changed obfuscation IS recorded (node is the source of truth).
	obf2 := obf
	obf2.Jc = obf.Jc + 1
	st.Amneziawg.Obfuscation = control.AmneziaWGToProto(obf2)
	recordNodeIdentity(ctx, conn, again, st, nil)
	final, err := fleet.GetNode(ctx, conn, node.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if final.Obfuscation != obf2 {
		t.Errorf("changed obfuscation not recorded: got %+v want %+v", final.Obfuscation, obf2)
	}
	if final.Version == again.Version {
		t.Error("a real identity change should bump the version")
	}
}
