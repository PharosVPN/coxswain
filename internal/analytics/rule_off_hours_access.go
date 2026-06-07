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

// ruleOffHoursAccess (info) flags a device connecting at an hour-of-day well
// outside its own historical pattern — a 3am login from a device that has only
// ever connected during business hours. It learns the per-device hour-of-day
// distribution from the FULL connection_events history and flags a window
// connect whose hour the device has used in only a tiny fraction of its history.
//
// FALSE-POSITIVE CONTROLS (this rule is deliberately conservative — an info-level
// behavioural hint must not cry wolf):
//   - Minimum history: the device must have at least offHoursMinConnects (20)
//     prior connects spread over at least offHoursMinDays (7) distinct calendar
//     days before its profile is trusted at all. Below that there is no baseline
//     and the rule stays silent — a new or lightly-used device is never flagged.
//   - Clear outliers only: an hour counts as "off hours" only if it appears in
//     <= offHoursMaxShare (2%) of all prior connects. An hour the device uses
//     even occasionally is treated as normal.
//   - Hours are bucketed in UTC, the storage timezone, so the baseline and the
//     observed connect are compared on the same clock (no DST/zone drift).
//
// Dedup is per (device, date): one alert per off-hours day, so a device poked at
// 3am twice in one night does not spam, but a recurrence on a later day opens a
// fresh alert. The key includes the connect's UTC date.
func ruleOffHoursAccess(ctx context.Context, db *sql.DB, dev deviceWindow, _ GeoResolver, _ time.Time) []Finding {
	// Earliest connect in the window bounds the baseline ("everything before").
	var windowStart time.Time
	for _, e := range dev.events {
		if e.EventType == "connect" {
			windowStart = e.At
			break
		}
	}
	if windowStart.IsZero() {
		return nil
	}

	hist, err := loadHourHistogram(ctx, db, dev.deviceID, windowStart)
	if err != nil {
		slog.Warn("analytics: off_hours histogram failed", "device", dev.deviceID, "err", err)
		return nil
	}
	// Conservative gate: require a meaningful, well-spread baseline.
	if hist.total < offHoursMinConnects || hist.distinctDays < offHoursMinDays {
		return nil
	}

	// Walk the window's connects; flag the first connect (per date) whose hour is
	// a clear outlier in the device's history.
	seenDates := map[string]bool{}
	var out []Finding
	for _, e := range dev.events {
		if e.EventType != "connect" {
			continue
		}
		hour := e.At.UTC().Hour()
		share := float64(hist.byHour[hour]) / float64(hist.total)
		if share > offHoursMaxShare {
			continue // an hour the device uses with any regularity — normal
		}
		date := e.At.UTC().Format("2006-01-02")
		if seenDates[date] {
			continue
		}
		seenDates[date] = true

		out = append(out, Finding{
			Kind:      KindOffHoursAccess,
			Severity:  SeverityInfo,
			DeviceID:  dev.deviceID,
			UserID:    dev.userID,
			NodeID:    e.NodeID,
			SourceIPs: nonEmpty(e.SourceIP),
			At:        e.At,
			// Per (device, date): one off-hours alert per day.
			DedupKey: KindOffHoursAccess + ":" + dev.deviceID + ":" + date,
			Detail: map[string]any{
				"hour_utc":          hour,
				"hour_share":        round4(share),
				"typical_hours_utc": hist.typicalHours(),
				"baseline_connects": hist.total,
				"baseline_days":     hist.distinctDays,
				"connect_at":        e.At.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}

// hourHistogram is a device's hour-of-day connect distribution (UTC), with the
// totals the off_hours gate needs.
type hourHistogram struct {
	byHour       [24]int // connects per UTC hour
	total        int     // total prior connects counted
	distinctDays int     // distinct UTC calendar days with a connect
}

// typicalHours returns the device's commonly-used hours (those at or above the
// outlier share), sorted — the "what's normal for this device" evidence.
func (h hourHistogram) typicalHours() []int {
	var out []int
	for hr := 0; hr < 24; hr++ {
		if h.total > 0 && float64(h.byHour[hr])/float64(h.total) > offHoursMaxShare {
			out = append(out, hr)
		}
	}
	sort.Ints(out)
	return out
}

// loadHourHistogram builds the per-UTC-hour connect histogram for a device over
// all connects strictly before `before`, plus the count of distinct days. It
// reads the raw timestamps and buckets in Go (rather than relying on a
// backend-specific date function) so the result is identical on SQLite and
// Postgres.
func loadHourHistogram(ctx context.Context, db *sql.DB, deviceID string, before time.Time) (hourHistogram, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT at FROM connection_events
		WHERE device_id = ? AND event_type = 'connect' AND at < ?`,
		deviceID, before.UTC())
	if err != nil {
		return hourHistogram{}, err
	}
	defer rows.Close()

	var h hourHistogram
	days := map[string]bool{}
	for rows.Next() {
		var at time.Time
		if err := rows.Scan(&at); err != nil {
			return hourHistogram{}, err
		}
		at = at.UTC()
		h.byHour[at.Hour()]++
		h.total++
		days[at.Format("2006-01-02")] = true
	}
	h.distinctDays = len(days)
	return h, rows.Err()
}
