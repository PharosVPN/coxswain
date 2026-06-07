// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package analytics is coxswain's anomaly-detection engine (Phase C). It sweeps
// the persisted connection_events session history (package monitor) on a
// periodic ticker, runs a set of rules over a bounded recent window, and
// upserts the findings as rows in the alerts table.
//
// Each rule is a small, self-contained function over the recent events for one
// device, returning []Finding; Sweep composes them. Findings are deduplicated
// by a stable DedupKey: while an alert with that key is still open, a repeated
// detection refreshes the existing row (bumping updated_at, merging evidence)
// rather than inserting a duplicate — so a persistent condition does not spam a
// new alert on every sweep. New (or newly-escalated) alerts are returned so the
// caller can fan them out to the live hub for real-time dashboards.
//
// Every rule MUST filter device_id IS NOT NULL: client sessions carry a device,
// while node-to-node cascade inner-links have a NULL device_id and are infra
// traffic, not a subject for anomaly detection.
package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// Severity levels for an alert.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert kinds — one per rule.
const (
	KindLeakedProfile      = "leaked_profile"
	KindImpossibleTravel   = "impossible_travel"
	KindConcurrentSessions = "concurrent_sessions"
	KindNewGeo             = "new_geo"
)

// Status values for an alert row.
const (
	StatusOpen         = "open"
	StatusAcknowledged = "acknowledged"
	StatusResolved     = "resolved"
)

// Tunable thresholds. Named constants so the detection policy is reviewable in
// one place rather than buried in each rule.
const (
	// DefaultWindow is how far back a sweep scans connection_events. A finding
	// is derived from events inside this window.
	DefaultWindow = 24 * time.Hour
	// DefaultInterval is the sweep cadence when none is configured.
	DefaultInterval = 60 * time.Second

	// leakedProfileWindow is the span within which connects from 2+ distinct
	// source IPs for one device are treated as a shared/leaked profile.
	leakedProfileWindow = 10 * time.Minute
	// leakedProfileMinIPs is how many distinct source IPs (within the window)
	// flag a leaked profile.
	leakedProfileMinIPs = 2

	// impossibleTravelMaxKMH is the implied ground speed above which two
	// consecutive connects are flagged as impossible travel. ~900 km/h is a
	// commercial jet's cruise; anything faster is physically implausible.
	impossibleTravelMaxKMH = 900.0
	// impossibleTravelMinKM ignores tiny hops between nearby cities where a
	// coarse GeoIP fix plus a short interval yields a meaningless speed.
	impossibleTravelMinKM = 100.0

	// concurrentMinNodes is how many distinct nodes a device must hold
	// overlapping active sessions on to flag concurrent sessions.
	concurrentMinNodes = 2

	// clockSkewTolerance is the assumed upper bound on inter-node wall-clock
	// drift. connection_events.at is each node's own wall-clock (no central
	// normalization), so two events from different nodes can disagree by up to
	// this much purely from NTP drift, not real elapsed time. Cross-node timing
	// rules treat any Δt at or below this as indistinguishable from skew /
	// simultaneity and refuse to draw a conclusion from it.
	clockSkewTolerance = 60 * time.Second

	// maxOpenSessionAge caps how long an unmatched (still-open) connect is
	// believed to run. A dropped disconnect (node restart, lost stream) would
	// otherwise leave a session open to `now`, manufacturing overlap with every
	// later session forever. Past this age an open session is treated as closed
	// at connect+maxOpenSessionAge, not `now`.
	maxOpenSessionAge = 30 * time.Minute
)

// Finding is one rule detection, before it is persisted. Sweep turns each
// Finding into an alerts row (insert or dedup-refresh).
type Finding struct {
	Kind      string
	Severity  string
	DeviceID  string
	UserID    string
	NodeID    string         // the most relevant node, when one applies
	SourceIPs []string       // the client IPs involved
	Detail    map[string]any // rule-specific evidence, JSON-encoded
	DedupKey  string         // stable key collapsing repeated detections
	At        time.Time      // when the condition was observed (event time)
}

// GeoResolver is the slice of geoip the engine needs, as an interface so tests
// can inject a fake without a downloaded MaxMind database. *geoip.Resolver
// satisfies it.
type GeoResolver interface {
	// Lookup resolves an IP (or host:port) to a location; ok is false for a
	// private/invalid IP or an unavailable database.
	Lookup(host string) (Location, bool)
}

// Location is a resolved IP location, mirroring geoip.Location's fields. The
// engine depends on this local shape (not the geoip package directly) so the
// resolver is trivially fakeable in tests.
type Location struct {
	City        string
	Country     string
	CountryCode string
	Latitude    float64
	Longitude   float64
}

// rule is one detector over the recent events of a single device. db is passed
// for the rules that consult history beyond the sweep window (new_geo's
// baseline); most rules ignore it and reason purely over dev.events.
type rule func(ctx context.Context, db *sql.DB, dev deviceWindow, geo GeoResolver, now time.Time) []Finding

// rules is the Tier-1 rule set, composed by Sweep. Adding a Tier-2/3 rule is a
// one-line append here plus its function.
var rules = []rule{
	ruleLeakedProfile,
	ruleImpossibleTravel,
	ruleConcurrentSessions,
	ruleNewGeo,
}

// Sweep runs every rule over the recent connection_events and upserts the
// resulting alerts. It looks back `window` (DefaultWindow when zero) from now,
// groups events by device (device_id IS NOT NULL only), runs each rule per
// device, and dedup-upserts the findings. It returns the alerts that were newly
// created or escalated this sweep (for live fan-out); refreshed dedup hits are
// not returned. Sweep is idempotent: a stable condition produces the same one
// open alert across repeated sweeps.
func Sweep(ctx context.Context, db *sql.DB, geo GeoResolver, now time.Time, window time.Duration) ([]Alert, error) {
	if window <= 0 {
		window = DefaultWindow
	}
	if geo == nil {
		geo = noGeo{}
	}
	since := now.Add(-window)

	devices, err := loadDeviceWindows(ctx, db, since, now)
	if err != nil {
		return nil, err
	}

	var fresh []Alert
	for _, dev := range devices {
		for _, r := range rules {
			for _, f := range r(ctx, db, dev, geo, now) {
				a, isNew, err := upsertAlert(ctx, db, f, now)
				if err != nil {
					slog.Warn("analytics: upsert alert failed", "kind", f.Kind, "device", f.DeviceID, "err", err)
					continue
				}
				if isNew {
					fresh = append(fresh, a)
				}
			}
		}
	}
	return fresh, nil
}

// noGeo is a GeoResolver that never resolves — used when none is supplied, so
// geo-dependent rules simply skip rather than panic.
type noGeo struct{}

func (noGeo) Lookup(string) (Location, bool) { return Location{}, false }
