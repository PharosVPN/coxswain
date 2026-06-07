// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package reconcile is coxswain's single config-delivery primitive plus the
// always-on sweep that keeps every node converged on its intended peer set
// (Phase 2, Option B). PushNode delivers coxswain's current desired state to one
// node — the same flow `cox nodes push` used to inline — and is the one path
// used by the CLI, push-on-provision, the admin API, and the reconcile sweep.
package reconcile

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/noderoute"
	"github.com/PharosVPN/coxswain/internal/profile"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ControlRPCTimeout bounds a single control-plane RPC during a push or sweep.
const ControlRPCTimeout = 10 * time.Second

// PushResult reports what a PushNode delivered to a node.
type PushResult struct {
	// AmneziaPeers is the number of AmneziaWG peers pushed (full-replace).
	AmneziaPeers int
	// PushedRevision is the AmneziaWG config revision coxswain assigned this push.
	PushedRevision int64
	// AppliedRevision is the revision the node acknowledged applying.
	AppliedRevision int64
	// Reloaded is whether the node reloaded its AmneziaWG data plane in place.
	Reloaded bool
	// XRaySkipped is true when an XRay push was attempted but the node has no
	// REALITY support (codes.Unimplemented) — tolerated, not fatal.
	XRaySkipped bool
	// XRayPeers is the number of XRay/REALITY clients pushed (0 when XRay is
	// disabled fleet-wide or the node skipped it).
	XRayPeers int
	// CascadeReapplied is true once the cascade edge peers were re-applied last.
	CascadeReapplied bool
}

// toAmneziaWGPeers converts coxswain's fleet.Peer rows for one node into the
// proto Peer messages PushAmneziaWGConfig expects. Non-AmneziaWG peers are
// skipped — XRay has its own encoder.
func toAmneziaWGPeers(peers []fleet.Peer) []*nodev1.Peer {
	out := make([]*nodev1.Peer, 0, len(peers))
	for _, p := range peers {
		if p.Protocol != profile.ProtocolAmneziaWG {
			continue
		}
		out = append(out, &nodev1.Peer{
			Id:           p.ID,
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    p.PublicKey,
			AllowedIps:   []string{p.AllowedIP},
			PresharedKey: p.PresharedKey,
		})
	}
	return out
}

// toXRayPeers converts coxswain's fleet.Peer rows for one node into the proto
// Peer messages PushXRayRealityConfig expects. For XRay the peer's PublicKey
// carries the VLESS UUID (the node uses it as the client id).
func toXRayPeers(peers []fleet.Peer) []*nodev1.Peer {
	out := make([]*nodev1.Peer, 0, len(peers))
	for _, p := range peers {
		if p.Protocol != profile.ProtocolXRayReality {
			continue
		}
		out = append(out, &nodev1.Peer{
			Id:        p.ID,
			Protocol:  nodev1.Protocol_PROTOCOL_XRAY_REALITY,
			PublicKey: p.PublicKey, // the VLESS UUID
			Flow:      p.Flow,
		})
	}
	return out
}

// pushClient is the subset of *control.Client the push core drives. Tests
// substitute a fake; production passes a real dialed client.
type pushClient interface {
	PushAmneziaWGConfig(ctx context.Context, revision int64, peers []*nodev1.Peer) (*nodev1.PushConfigResponse, error)
	PushXRayRealityConfig(ctx context.Context, revision int64, peers []*nodev1.Peer, dest string, serverNames, shortIDs []string, port uint32) (*nodev1.PushConfigResponse, error)
}

// cascadeReconciler re-applies the cascade edge peers + transits for every path
// traversing a node. *cascade.Coordinator satisfies it; tests substitute a fake.
type cascadeReconciler interface {
	ReconcileNode(ctx context.Context, nodeID string) error
}

// PushNode delivers coxswain's current desired state to one node — the single
// control-plane delivery primitive (Phase 2). It dials the node over its
// persisted route, full-replaces its AmneziaWG peer set (assigning a fresh
// monotonic revision), conditionally pushes the XRay/REALITY set + camouflage
// policy (tolerating a node without REALITY support), and finally re-applies the
// cascade edge peers — which the AmneziaWG full-replace wipes — so they re-own
// the device IPs. The cascade reconcile MUST run last.
func PushNode(ctx context.Context, cfg *config.Config, conn *sql.DB, node fleet.Node) (PushResult, error) {
	if node.ControlAddr == "" {
		return PushResult{}, fmt.Errorf("node %s has no control address", node.ID)
	}

	dialer, err := noderoute.NewControlDialer(ctx, conn, noderoute.NodeRoute(ctx, conn, node))
	if err != nil {
		return PushResult{}, err
	}
	client, err := dialer.Dial(node.ControlAddr)
	if err != nil {
		return PushResult{}, err
	}
	defer client.Close()

	coord, err := noderoute.NewCascadeCoordinator(ctx, conn)
	if err != nil {
		return PushResult{}, err
	}
	return pushNode(ctx, cfg, conn, node, client, coord)
}

// pushNode is the injectable core of PushNode: it carries no I/O setup (no
// dialing, no coordinator construction), so the AmneziaWG full-replace, the
// XRay Unimplemented-tolerance, and the cascade re-apply are all unit-testable
// against fakes. Production wires the real dialed client + cascade coordinator.
func pushNode(ctx context.Context, cfg *config.Config, conn *sql.DB, node fleet.Node, client pushClient, coord cascadeReconciler) (PushResult, error) {
	var res PushResult

	peers, err := fleet.ListPeersByNode(ctx, conn, node.ID)
	if err != nil {
		return res, err
	}
	amneziaPeers := toAmneziaWGPeers(peers)
	res.AmneziaPeers = len(amneziaPeers)

	revision, err := fleet.NextNodeConfigRevision(ctx, conn, node.ID)
	if err != nil {
		return res, err
	}
	res.PushedRevision = revision

	rpcCtx, cancel := context.WithTimeout(ctx, ControlRPCTimeout)
	defer cancel()
	resp, err := client.PushAmneziaWGConfig(rpcCtx, revision, amneziaPeers)
	if err != nil {
		return res, fmt.Errorf("control %s: %w", node.ControlAddr, err)
	}
	res.AppliedRevision = resp.GetAppliedRevision()
	res.Reloaded = resp.GetReloaded()

	// XRay/REALITY: push the VLESS client set + the fleet's camouflage policy
	// (decoy dest, accepted SNI, shortIds, port) so the node brings its REALITY
	// server up. Skipped when XRay is disabled fleet-wide; a node built without
	// REALITY (e.g. a cascade exit that only carries AmneziaWG) reports
	// Unimplemented, which we tolerate so the cascade reconcile below still runs —
	// aborting here would leave its edge peer wiped by the AmneziaWG replace.
	if cfg.Protocols.XRay {
		xrayPeers := toXRayPeers(peers)
		dest, serverNames := profile.RealityCamouflage(cfg.Reality.DecoySite)
		xrayRev, rErr := fleet.NextNodeConfigRevision(ctx, conn, node.ID)
		if rErr != nil {
			return res, rErr
		}
		_, xErr := client.PushXRayRealityConfig(rpcCtx, xrayRev, xrayPeers,
			dest, serverNames, []string{""}, uint32(profile.XRayListenPort))
		switch {
		case status.Code(xErr) == codes.Unimplemented:
			res.XRaySkipped = true
		case xErr != nil:
			return res, fmt.Errorf("control %s (xray): %w", node.ControlAddr, xErr)
		default:
			res.XRayPeers = len(xrayPeers)
		}
	}

	// A device-peer push full-replaces awg0, wiping any cascade edge peer this
	// node carries as an exit/mid hop. Re-apply the cascade state so those edge
	// peers are re-added last (so they re-own the device IPs).
	if err := coord.ReconcileNode(ctx, node.ID); err != nil {
		return res, fmt.Errorf("re-apply cascade peers on %s: %w", node.Name, err)
	}
	res.CascadeReapplied = true
	return res, nil
}
