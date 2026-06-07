// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// ruleNewGeo (info) flags a device connecting from a country it has no prior
// history of, over the FULL connection_events history for that device (not just
// the sweep window). It is informational — a user travelling is normal — but a
// first-ever connect from a new country is worth surfacing for review.
//
// For each connect in the window, it geolocates the source IP to a country and
// compares against the device's historical country set (connects strictly
// before the window). A country present in the window but absent from history
// is a finding. Dedup is per (device, country): each new country opens its own
// alert, but a repeat connect from the same new country refreshes rather than
// duplicates.
func ruleNewGeo(ctx context.Context, db *sql.DB, dev deviceWindow, geo GeoResolver, _ time.Time) []Finding {
	// Earliest connect in the window — the baseline is "everything before this".
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

	prior, err := priorCountries(ctx, db, geo, dev.deviceID, windowStart)
	if err != nil {
		slog.Warn("analytics: new_geo prior countries failed", "device", dev.deviceID, "err", err)
		return nil
	}

	// Walk the window's connects; the first connect from each as-yet-unseen
	// country (not in prior, not already flagged this sweep) is a finding.
	seenThisSweep := map[string]bool{}
	var out []Finding
	for _, e := range dev.events {
		if e.EventType != "connect" || e.SourceIP == "" {
			continue
		}
		loc, ok := geo.Lookup(e.SourceIP)
		if !ok || loc.CountryCode == "" {
			continue
		}
		cc := loc.CountryCode
		if prior[cc] || seenThisSweep[cc] {
			continue
		}
		seenThisSweep[cc] = true
		out = append(out, Finding{
			Kind:      KindNewGeo,
			Severity:  SeverityInfo,
			DeviceID:  dev.deviceID,
			UserID:    dev.userID,
			NodeID:    e.NodeID,
			SourceIPs: []string{e.SourceIP},
			At:        e.At,
			// Per (device, country): a new country is its own alert.
			DedupKey: KindNewGeo + ":" + dev.deviceID + ":" + cc,
			Detail: map[string]any{
				"country":      cc,
				"country_name": loc.Country,
				"city":         loc.City,
				"source_ip":    e.SourceIP,
				"first_seen":   e.At.UTC().Format(time.RFC3339),
			},
		})
	}
	return out
}
