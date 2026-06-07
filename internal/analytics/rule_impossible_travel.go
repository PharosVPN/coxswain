// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"time"
)

// ruleImpossibleTravel (critical) flags a device whose two consecutive connects
// come from source IPs whose GeoIP locations imply a ground speed faster than a
// commercial jet (impossibleTravelMaxKMH). That is physically impossible for
// one device, so the profile is in two places at once — a strong leak signal.
//
// It walks consecutive connects (by distinct source IP), geolocates each, and
// computes haversine distance / time delta. A pair is skipped when either IP
// does not geolocate (private/unknown) or the hop is shorter than
// impossibleTravelMinKM (a coarse city-level fix over a short interval yields a
// meaningless speed). The fastest offending pair becomes the finding.
//
// connection_events.at is the reporting NODE's own wall-clock — different nodes,
// independent NTP, no central normalization — so a cross-node Δt can be off by
// up to clockSkewTolerance purely from drift (and can even be zero or slightly
// negative for near-simultaneous connects). This rule is therefore skew-tolerant:
// it never clamps a zero/near-zero Δt to a huge speed (that would fabricate a
// CRITICAL from mere simultaneity), it skips any pair with Δt <= clockSkewTolerance
// entirely, and for the rest it computes speed over the conservative lower-bound
// elapsed time (Δt − clockSkewTolerance) so a flagged hop is genuinely too fast
// even after granting the worst-case drift in the device's favour.
func ruleImpossibleTravel(_ context.Context, _ *sql.DB, dev deviceWindow, geo GeoResolver, _ time.Time) []Finding {
	// Reduce to consecutive connects whose source IP actually changed; a stream
	// of connects from one IP can't imply travel.
	type located struct {
		ev  event
		loc Location
	}
	var pts []located
	var lastIP string
	for _, e := range dev.events {
		if e.EventType != "connect" || e.SourceIP == "" {
			continue
		}
		if e.SourceIP == lastIP {
			continue // same IP back-to-back; no movement
		}
		loc, ok := geo.Lookup(e.SourceIP)
		if !ok {
			lastIP = e.SourceIP // unresolved breaks the chain at this point
			continue
		}
		pts = append(pts, located{ev: e, loc: loc})
		lastIP = e.SourceIP
	}
	if len(pts) < 2 {
		return nil
	}

	var best *Finding
	var bestKMH float64
	for i := 1; i < len(pts); i++ {
		a, b := pts[i-1], pts[i]
		if a.ev.SourceIP == b.ev.SourceIP {
			continue
		}
		km := haversineKM(a.loc.Latitude, a.loc.Longitude, b.loc.Latitude, b.loc.Longitude)
		if km < impossibleTravelMinKM {
			continue
		}
		// Δt is two node wall-clocks subtracted, so it carries up to
		// clockSkewTolerance of NTP drift (and can be zero/negative for a
		// near-simultaneous pair). At or below that bound we cannot tell
		// impossible travel from skew/simultaneity — skip, never clamp to a
		// large speed.
		dt := b.ev.At.Sub(a.ev.At)
		if dt <= clockSkewTolerance {
			continue
		}
		// Grant the worst-case drift in the device's favour: compute speed over
		// the conservative LOWER-BOUND elapsed time (Δt − clockSkewTolerance).
		// dt > clockSkewTolerance here, so this is strictly positive.
		hours := (dt - clockSkewTolerance).Hours()
		kmh := km / hours
		if kmh <= impossibleTravelMaxKMH {
			continue
		}
		if best == nil || kmh > bestKMH {
			bestKMH = kmh
			minutes := round2(b.ev.At.Sub(a.ev.At).Minutes())
			f := Finding{
				Kind:      KindImpossibleTravel,
				Severity:  SeverityCritical,
				DeviceID:  dev.deviceID,
				UserID:    dev.userID,
				NodeID:    b.ev.NodeID,
				SourceIPs: []string{a.ev.SourceIP, b.ev.SourceIP},
				At:        b.ev.At,
				// One open alert per device for the impossible-travel condition.
				DedupKey: KindImpossibleTravel + ":" + dev.deviceID,
				Detail: map[string]any{
					"from": map[string]any{
						"ip": a.ev.SourceIP, "city": a.loc.City, "country": a.loc.CountryCode,
						"lat": a.loc.Latitude, "lon": a.loc.Longitude,
						"at": a.ev.At.UTC().Format(time.RFC3339),
					},
					"to": map[string]any{
						"ip": b.ev.SourceIP, "city": b.loc.City, "country": b.loc.CountryCode,
						"lat": b.loc.Latitude, "lon": b.loc.Longitude,
						"at": b.ev.At.UTC().Format(time.RFC3339),
					},
					"distance_km": round2(km),
					"minutes":     minutes,
					"implied_kmh": round2(kmh),
					"max_kmh":     impossibleTravelMaxKMH,
				},
			}
			best = &f
		}
	}
	if best == nil {
		return nil
	}
	return []Finding{*best}
}
