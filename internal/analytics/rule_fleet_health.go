// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

// ruleFleetHealth (warning; critical when errored) flags a node that has fallen
// out of healthy operation: StatusUnreachable (missed control-plane heartbeats)
// is a warning, StatusError (provisioning/enrollment failure) is critical. The
// alert is node-scoped — device_id is null, node_id carries the node — since it
// is fleet infrastructure health, not a client anomaly.
//
// AUTO-RESOLVE: a fleet_health alert describes a transient operational state, so
// it must clear itself when the node recovers — otherwise a flapped node leaves
// a stale "unreachable" alert open forever. On every sweep this rule walks the
// full node inventory; for each node now StatusActive it resolves any open
// fleet_health alert keyed to it (resolveOpenByDedup, a no-op when none is
// open). So the alert opens when the node degrades and closes the first sweep
// after it heals, with no operator action.
//
// Dedup is per node: one open fleet_health alert per node. A node that goes
// unreachable then errors refreshes the same alert (key is per-node, not
// per-status); the evidence records the current status.
func ruleFleetHealth(ctx context.Context, db *sql.DB, _, now time.Time) []Finding {
	nodes, err := fleet.ListNodes(ctx, db)
	if err != nil {
		slog.Warn("analytics: fleet_health list nodes failed", "err", err)
		return nil
	}

	var out []Finding
	for _, n := range nodes {
		dedup := KindFleetHealth + ":" + n.ID
		switch n.Status {
		case fleet.StatusUnreachable, fleet.StatusError:
			severity := SeverityWarning
			if n.Status == fleet.StatusError {
				severity = SeverityCritical
			}
			out = append(out, Finding{
				Kind:     KindFleetHealth,
				Severity: severity,
				NodeID:   n.ID,
				At:       now,
				DedupKey: dedup,
				Detail: map[string]any{
					"node_id":     n.ID,
					"node_name":   n.Name,
					"node_status": n.Status,
					"region":      n.Region,
				},
			})
		case fleet.StatusActive:
			// Node healthy again — clear any open fleet_health alert for it.
			if err := resolveOpenByDedup(ctx, db, dedup, now); err != nil {
				slog.Warn("analytics: fleet_health auto-resolve failed", "node", n.ID, "err", err)
			}
		}
	}
	return out
}
