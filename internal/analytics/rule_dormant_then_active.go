// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// ruleDormantThenActive (info) flags a device that reactivates after a long
// silence: a fresh connect in the sweep window whose immediately-preceding
// connect (over the FULL history) was more than dormantThreshold (30d) earlier.
// A long-idle credential suddenly coming alive is a soft signal — the user may
// simply be back from a long trip — but worth surfacing, since a dormant profile
// reactivating is also what a leaked-but-unused bundle looks like when it is
// finally exercised.
//
// It takes the earliest connect in the window as the "fresh" connect, then looks
// up the latest connect STRICTLY BEFORE it across all history. If that prior
// connect exists and the gap exceeds the threshold, it fires. A device with no
// prior connect (its first ever) is not dormant-then-active — there is no
// dormancy to break — so it is skipped. Dedup is per-device and refreshable.
func ruleDormantThenActive(ctx context.Context, db *sql.DB, dev deviceWindow, _ GeoResolver, _ time.Time) []Finding {
	var fresh *event
	for i := range dev.events {
		if dev.events[i].EventType == "connect" {
			fresh = &dev.events[i] // earliest connect in the window
			break
		}
	}
	if fresh == nil {
		return nil
	}

	// The most recent connect strictly before this fresh one, over all history.
	// Selecting the raw `at` column (ORDER BY ... DESC LIMIT 1) rather than
	// MAX(at) preserves the column's TIMESTAMP type affinity so it scans into a
	// time.Time across backends (a MAX() aggregate loses that affinity on SQLite).
	var prior time.Time
	err := db.QueryRowContext(ctx, `
		SELECT at FROM connection_events
		WHERE device_id = ? AND event_type = 'connect' AND at < ?
		ORDER BY at DESC LIMIT 1`,
		dev.deviceID, fresh.At.UTC()).Scan(&prior)
	switch {
	case err == sql.ErrNoRows:
		return nil // no prior connect: first activity ever, not a reactivation
	case err != nil:
		slog.Warn("analytics: dormant_then_active prior connect lookup failed", "device", dev.deviceID, "err", err)
		return nil
	}
	prior = prior.UTC()

	gap := fresh.At.UTC().Sub(prior)
	if gap <= dormantThreshold {
		return nil // active recently enough — not dormant
	}

	return []Finding{{
		Kind:      KindDormantThenActive,
		Severity:  SeverityInfo,
		DeviceID:  dev.deviceID,
		UserID:    dev.userID,
		NodeID:    fresh.NodeID,
		SourceIPs: nonEmpty(fresh.SourceIP),
		At:        fresh.At,
		// One open alert per device; a continuing reactivation refreshes it.
		DedupKey: KindDormantThenActive + ":" + dev.deviceID,
		Detail: map[string]any{
			"dormant_days":     int(gap.Hours() / 24),
			"dormant_duration": gap.Round(time.Hour).String(),
			"prior_connect":    prior.Format(time.RFC3339),
			"new_connect":      fresh.At.UTC().Format(time.RFC3339),
			"source_ip":        fresh.SourceIP,
		},
	}}
}
