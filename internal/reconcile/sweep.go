// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package reconcile

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/noderoute"
)

// Logf is the sweep's logging sink — a printf-style function (e.g. fmt.Printf or
// a wrapper that prefixes a line). A nil Logf disables logging.
type Logf func(format string, args ...any)

// amneziaWGService returns the AmneziaWG ServiceStatus from a GetStatus response,
// or nil when the node reported none.
func amneziaWGService(s *nodev1.GetStatusResponse) *nodev1.ServiceStatus {
	for _, svc := range s.GetServices() {
		if svc.GetProtocol() == nodev1.Protocol_PROTOCOL_AMNEZIAWG {
			return svc
		}
	}
	return nil
}

// needsReconcile is the sweep's pure decision: given a node's live GetStatus and
// its intended config revision, decide whether to heal it with a push, and why.
// Two signatures trigger a heal:
//   - DRIFT: the node's applied_revision is behind coxswain's intended revision
//     (a re-provision changed intent without a push reaching the node).
//   - STALE: the AmneziaWG service has peers but zero recent handshakes — a
//     running+listening data plane that is silently broken.
//
// It is a pure function (no I/O), so the sweep's logic is unit-testable without a
// live node.
func needsReconcile(s *nodev1.GetStatusResponse, intendedRev int64) (push, stale bool, reason string) {
	if applied := s.GetAppliedRevision(); applied < intendedRev {
		return true, false, fmt.Sprintf("DRIFT (applied %d < intended %d)", applied, intendedRev)
	}
	if svc := amneziaWGService(s); svc != nil {
		if svc.GetPeerCount() > 0 && svc.GetHandshakingPeers() == 0 {
			return true, true, fmt.Sprintf("STALE (%d peers, 0 handshaking)", svc.GetPeerCount())
		}
	}
	return false, false, ""
}

// staleHealCooldown rate-limits STALE-triggered re-pushes per node. A node with
// provisioned peers but nobody currently connected reports zero handshakes every
// pass; we must not re-push it (and bump its config_revision) every tick. A
// genuinely-broken plane still gets one heal attempt per cooldown.
const staleHealCooldown = 5 * time.Minute

// shouldHeal decides whether a node needsReconcile flagged should actually be
// pushed THIS pass. DRIFT heals are unconditional — a push makes applied ==
// intended, so they never loop. STALE heals are rate-limited per node via
// healedAt so an idle node isn't hammered every interval.
func shouldHeal(stale bool, nodeID string, healedAt map[string]time.Time, now time.Time, cooldown time.Duration) bool {
	if !stale {
		return true
	}
	if last, ok := healedAt[nodeID]; ok && now.Sub(last) < cooldown {
		return false
	}
	return true
}

// SweepOnce runs one pass of the reconcile sweep over every node: for each node
// it queries live status, marks unreachable nodes, and heals drift/stale nodes
// with a PushNode. One node's failure never stops the pass — the loop logs and
// continues. It returns the number of nodes it healed (or attempted to heal).
//
// This is the heart of Option B: an always-on controller that closes the gap
// where a re-provision changed a node's intended peer set but no push reached it,
// so the node served stale config while reporting healthy.
func SweepOnce(ctx context.Context, cfg *config.Config, conn *sql.DB, logf Logf, staleHealedAt map[string]time.Time) int {
	log := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}
	if staleHealedAt == nil {
		staleHealedAt = map[string]time.Time{}
	}
	nodes, err := fleet.ListNodes(ctx, conn)
	if err != nil {
		log("reconcile: list nodes failed: %v", err)
		return 0
	}

	healed := 0
	for _, node := range nodes {
		if ctx.Err() != nil {
			return healed
		}
		if node.ControlAddr == "" {
			continue // not yet enrolled — nothing to reconcile
		}

		st, err := nodeStatus(ctx, conn, node)
		if err != nil {
			// Dial/RPC failed: the node is not answering its control plane. Mark it
			// unreachable (the constant existed but was never set before Phase 2) and
			// move on — one node's silence must not stall the whole sweep.
			if sErr := fleet.SetNodeStatus(ctx, conn, node.ID, fleet.StatusUnreachable); sErr != nil {
				log("reconcile: %s set unreachable failed: %v", node.Name, sErr)
			}
			log("reconcile: %s unreachable (%v)", node.Name, err)
			continue
		}

		// Record the AmneziaWG/XRay identity the node reports (from its persisted
		// first-run keypair, available before any push). This is what makes a
		// freshly-onboarded node provisionable automatically — no manual
		// `cox nodes status`. Zero extra RPC cost: st is already in hand.
		recordNodeIdentity(ctx, conn, node, st, logf)

		push, stale, reason := needsReconcile(st, node.ConfigRevision)
		if !push {
			// Healthy + in sync: clear any prior unreachable/error status.
			if node.Status != fleet.StatusActive {
				_ = fleet.SetNodeStatus(ctx, conn, node.ID, fleet.StatusActive)
			}
			continue
		}
		if !shouldHeal(stale, node.ID, staleHealedAt, time.Now(), staleHealCooldown) {
			// STALE but recently healed — don't re-push an idle node every tick;
			// still visible via `cox nodes status` (⚠ STALE) for an operator.
			log("reconcile: %s %s — within stale cooldown, not re-pushing", node.Name, reason)
			continue
		}
		if stale {
			staleHealedAt[node.ID] = time.Now()
		}

		log("reconcile: healing %s — %s", node.Name, reason)
		if _, err := PushNode(ctx, cfg, conn, node); err != nil {
			log("reconcile: %s heal push failed: %v", node.Name, err)
			_ = fleet.SetNodeStatus(ctx, conn, node.ID, fleet.StatusError)
			continue
		}
		_ = fleet.SetNodeStatus(ctx, conn, node.ID, fleet.StatusActive)
		healed++
	}
	return healed
}

// recordNodeIdentity persists the AmneziaWG + XRay server identity a node reports
// in its live status, so a node becomes provisionable on the first sweep that
// reaches it — without an operator running `cox nodes status`. node is the source
// of truth (DESIGN §3). The write is skipped when the reported values already
// match what's stored, so a stable node never churns its version every pass.
func recordNodeIdentity(ctx context.Context, conn *sql.DB, node fleet.Node, st *nodev1.GetStatusResponse, logf Logf) {
	log := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}
	if pubKey, obf := control.AmneziaWGFromStatus(st); pubKey != "" &&
		(pubKey != node.WGPublicKey || obf != node.Obfuscation) {
		if err := fleet.SetNodeAmneziaWG(ctx, conn, node.ID, pubKey, obf); err != nil {
			log("reconcile: %s record amneziawg identity failed: %v", node.Name, err)
		} else {
			log("reconcile: %s recorded amneziawg identity", node.Name)
		}
	}
	if xpk := control.XRayFromStatus(st); xpk != "" && xpk != node.XRayPublicKey {
		if err := fleet.SetNodeXRayReality(ctx, conn, node.ID, xpk); err != nil {
			log("reconcile: %s record xray identity failed: %v", node.Name, err)
		}
	}
}

// nodeStatus dials a node over its persisted route and returns its GetStatus.
func nodeStatus(ctx context.Context, conn *sql.DB, node fleet.Node) (*nodev1.GetStatusResponse, error) {
	dialer, err := noderoute.NewControlDialer(ctx, conn, noderoute.NodeRoute(ctx, conn, node))
	if err != nil {
		return nil, err
	}
	client, err := dialer.Dial(node.ControlAddr)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	rpcCtx, cancel := context.WithTimeout(ctx, ControlRPCTimeout)
	defer cancel()
	return client.Status(rpcCtx)
}

// Run is the always-on reconcile sweep: every interval (until ctx is cancelled)
// it runs one SweepOnce pass. It is the backstop that makes drift self-heal even
// when a push-on-provision was missed. interval clamps to a sane minimum.
func Run(ctx context.Context, cfg *config.Config, conn *sql.DB, interval time.Duration, logf Logf) {
	if interval <= 0 {
		interval = time.Duration(config.DefaultReconcileSeconds) * time.Second
	}
	// Per-node STALE-heal timestamps, persisted across passes so an idle node
	// isn't re-pushed every interval (DRIFT heals stay unconditional).
	staleHealedAt := map[string]time.Time{}
	// Reconcile once immediately on startup: heals any drift that accumulated
	// while the controller was down (e.g. across a controller restart) without
	// waiting a full interval.
	SweepOnce(ctx, cfg, conn, logf, staleHealedAt)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			SweepOnce(ctx, cfg, conn, logf, staleHealedAt)
		}
	}
}
