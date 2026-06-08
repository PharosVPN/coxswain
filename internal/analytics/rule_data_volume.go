// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"sort"
	"time"
)

// ruleDataVolumeExfil (warning) flags a single device session that moved an
// anomalous amount of OUTBOUND data — tx_bytes is bytes leaving the client
// toward the tunnel, the direction a bulk-extraction / exfiltration shows up in.
// It fires on a window disconnect whose tx_bytes exceeds BOTH an absolute floor
// AND a large multiple of the device's own historical median session tx_bytes.
//
// FALSE-POSITIVE CONTROLS (this is a deliberately conservative heuristic — a
// large upload is a normal thing, so all three gates must hold before it fires):
//   - Minimum history: the device must have at least dataVolumeMinSessions (20)
//     prior COMPLETED sessions (disconnect rows carrying a byte delta) before its
//     median is trusted at all. A thin-history device has no stable baseline —
//     one or two sessions make any later session look like a multiple — so it is
//     never flagged.
//   - Absolute floor: the session's tx_bytes must clear dataVolumeFloorBytes
//     (1 GiB). A huge multiple of a tiny baseline (e.g. 50× of 2 MB = 100 MB) is
//     not enough data leaving to be worth surfacing.
//   - Relative factor: the session's tx_bytes must exceed dataVolumeFactor (10×)
//     the device's MEDIAN prior session tx_bytes. A heavy user whose median is
//     already large needs a proportionally larger session to trip this, so a
//     normal big upload by a high-volume device does not alert — its median is
//     high, so the 10× bar is high too. The median (not the mean) is used so a
//     single past spike does not inflate the baseline and mask a later one.
//
// Only window DISCONNECT rows are candidates: a connect row carries 0 bytes (the
// byte delta is stamped at session end), so the session's transferred volume is
// only known once it closes. Dedup is per (device, date): one alert per device
// per UTC day, so a device that closes several large sessions in a day does not
// spam, but a recurrence on a later day opens a fresh alert.
func ruleDataVolumeExfil(ctx context.Context, db *sql.DB, dev deviceWindow, _ GeoResolver, _ time.Time) []Finding {
	// Candidate sessions: window disconnects that actually moved outbound data.
	// (A 0-byte disconnect cannot clear the floor, so skip it cheaply.)
	var candidates []event
	for _, e := range dev.events {
		if e.EventType == "disconnect" {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Baseline: the median tx_bytes over the device's completed sessions strictly
	// before the window, plus how many there are. The baseline is "everything
	// before the window" (mirroring off_hours), so all candidates this sweep are
	// judged against one stable, pre-window median rather than a shifting one.
	windowStart := dev.events[0].At // events are ascending by At
	median, n, err := medianSessionTxBytes(ctx, db, dev.deviceID, windowStart)
	if err != nil {
		slog.Warn("analytics: data_volume median lookup failed", "device", dev.deviceID, "err", err)
		return nil
	}
	if n < dataVolumeMinSessions {
		return nil // thin history — no trusted baseline, never flag
	}

	threshold := median * dataVolumeFactor // the per-device relative bar (bytes)

	seenDates := map[string]bool{}
	var out []Finding
	for _, e := range candidates {
		tx := e.TxBytes
		// Both gates required: absolute floor AND the relative factor.
		if tx < dataVolumeFloorBytes || tx <= threshold {
			continue
		}
		date := e.At.UTC().Format("2006-01-02")
		if seenDates[date] {
			continue // one alert per (device, day); largest is reported first below
		}
		seenDates[date] = true

		out = append(out, Finding{
			Kind:      KindDataVolumeExfil,
			Severity:  SeverityWarning,
			DeviceID:  dev.deviceID,
			UserID:    dev.userID,
			NodeID:    e.NodeID,
			SourceIPs: nonEmpty(e.SourceIP),
			At:        e.At,
			// Per (device, date): one data-volume alert per day.
			DedupKey: KindDataVolumeExfil + ":" + dev.deviceID + ":" + date,
			Detail: map[string]any{
				"tx_bytes":           tx,
				"median_tx_bytes":    median,
				"factor_over_median": ratio(tx, median),
				"factor_threshold":   dataVolumeFactor,
				"floor_bytes":        int64(dataVolumeFloorBytes),
				"baseline_sessions":  n,
				"node_id":            e.NodeID,
				"source_ip":          e.SourceIP,
				"session_end":        e.At.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}

// medianSessionTxBytes returns the median tx_bytes over a device's COMPLETED
// sessions (disconnect rows) strictly before `before`, and the count of those
// sessions. It reads the raw tx_bytes and computes the median in Go (rather than
// a backend-specific percentile function) so the result is identical on SQLite
// and Postgres. Only disconnect rows are counted: a session's transferred volume
// is stamped at its end, so connect rows (always 0) would otherwise drag the
// median to 0 and make every later session look like an infinite multiple.
func medianSessionTxBytes(ctx context.Context, db *sql.DB, deviceID string, before time.Time) (median uint64, count int, err error) {
	rows, err := db.QueryContext(ctx, `
		SELECT tx_bytes FROM connection_events
		WHERE device_id = ? AND event_type = 'disconnect' AND at < ?`,
		deviceID, before.UTC())
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var vals []uint64
	for rows.Next() {
		var tx uint64
		if err := rows.Scan(&tx); err != nil {
			return 0, 0, err
		}
		vals = append(vals, tx)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	return medianU64(vals), len(vals), nil
}

// medianU64 returns the median of a slice of byte counts (0 for an empty slice).
// For an even count it averages the two middle elements, rounding down — exact
// enough for a 10× threshold comparison.
func medianU64(vals []uint64) uint64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	sorted := make([]uint64, n)
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	mid := n / 2
	if n%2 == 1 {
		return sorted[mid]
	}
	// Average the two middle values; halve each first to avoid overflowing uint64
	// on two near-max byte counts, then add (the dropped low bits are negligible).
	return sorted[mid-1]/2 + sorted[mid]/2
}

// ratio is the multiple of base that v represents, rounded to 4 places for
// compact JSON evidence. A zero base (shouldn't reach here — min-history gates
// it) yields 0 rather than dividing by zero.
func ratio(v, base uint64) float64 {
	if base == 0 {
		return 0
	}
	return round4(float64(v) / float64(base))
}
