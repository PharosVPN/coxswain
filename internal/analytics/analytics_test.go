// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/idgen"
)

// fixedNow is the stable reference time every test sweeps at, so windows and
// speeds are deterministic.
var fixedNow = time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

// fakeGeo is an injectable GeoResolver mapping known IPs to fixed locations, so
// the impossible-travel and new-geo rules never depend on a downloaded MaxMind
// database. An IP not in the map (or a private one) resolves to ok=false.
type fakeGeo map[string]Location

func (g fakeGeo) Lookup(host string) (Location, bool) {
	loc, ok := g[host]
	return loc, ok
}

// City fixtures (approximate coordinates) for the geo rules.
var (
	locNYC    = Location{City: "New York", Country: "United States", CountryCode: "US", Latitude: 40.71, Longitude: -74.01}
	locLondon = Location{City: "London", Country: "United Kingdom", CountryCode: "GB", Latitude: 51.51, Longitude: -0.13}
	locTokyo  = Location{City: "Tokyo", Country: "Japan", CountryCode: "JP", Latitude: 35.68, Longitude: 139.69}
	locNewark = Location{City: "Newark", Country: "United States", CountryCode: "US", Latitude: 40.74, Longitude: -74.17}
)

func testDB(t *testing.T) *sql.DB {
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

// seedEvent inserts one connection_events row directly, so tests control the
// device_id (including NULL), timing, source IP, and event type exactly.
func seedEvent(t *testing.T, conn *sql.DB, deviceID, nodeID, eventType, sourceIP string, at time.Time) {
	t.Helper()
	var dev any
	if deviceID == "" {
		dev = nil // NULL device_id — an infra link the rules must ignore
	} else {
		dev = deviceID
	}
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO connection_events
		(id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`,
		idgen.New("cev"), at.UTC(), nodeID, "pk", dev, "usr_1", "amneziawg", eventType, sourceIP, sourceIP+":1194")
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

// openAlerts returns all open alerts of a given kind.
func alertsOfKind(t *testing.T, conn *sql.DB, kind string) []Alert {
	t.Helper()
	all, err := Query(context.Background(), conn, Filter{Kind: kind, Limit: MaxLimit})
	if err != nil {
		t.Fatalf("query %s: %v", kind, err)
	}
	return all
}

func sweep(t *testing.T, conn *sql.DB, geo GeoResolver) []Alert {
	t.Helper()
	fresh, err := Sweep(context.Background(), conn, geo, fixedNow, DefaultWindow)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	return fresh
}

// --- leaked_profile -------------------------------------------------------

func TestLeakedProfileFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_leak"
	// Two connects from two distinct IPs within 10 minutes.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-9*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-5*time.Minute))

	fresh := sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindLeakedProfile)
	if len(got) != 1 {
		t.Fatalf("leaked_profile: got %d alerts want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityWarning {
		t.Errorf("severity = %q want warning", a.Severity)
	}
	if a.DeviceID != dev {
		t.Errorf("device = %q want %q", a.DeviceID, dev)
	}
	if len(a.SourceIPs) != 2 {
		t.Errorf("source_ips = %v want 2 distinct", a.SourceIPs)
	}
	if a.Detail["distinct_ips"].(float64) != 2 {
		t.Errorf("detail distinct_ips = %v want 2", a.Detail["distinct_ips"])
	}
	// The fresh slice should carry the new alert for live fan-out.
	if !containsKind(fresh, KindLeakedProfile) {
		t.Errorf("fresh alerts %v missing leaked_profile", fresh)
	}
}

func TestLeakedProfileBenignSingleIP(t *testing.T) {
	conn := testDB(t)
	dev := "dev_ok"
	// Many connects but all from ONE IP — normal reconnects, no leak.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-9*time.Minute))
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-5*time.Minute))
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-1*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindLeakedProfile); len(got) != 0 {
		t.Fatalf("benign single-IP produced %d leaked_profile alerts want 0", len(got))
	}
}

func TestLeakedProfileBenignOutsideWindow(t *testing.T) {
	conn := testDB(t)
	dev := "dev_slow"
	// Two distinct IPs, but ~3h apart — outside the 10m leak window.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-5*time.Hour))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-2*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindLeakedProfile); len(got) != 0 {
		t.Fatalf("IPs outside leak window produced %d alerts want 0", len(got))
	}
}

// --- impossible_travel ----------------------------------------------------

func TestImpossibleTravelFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_travel"
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locTokyo}
	// NYC then Tokyo (~10,800 km) 30 minutes apart → ~21,000 km/h, impossible.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-50*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-20*time.Minute))

	sweep(t, conn, geo)

	got := alertsOfKind(t, conn, KindImpossibleTravel)
	if len(got) != 1 {
		t.Fatalf("impossible_travel: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %q want critical", a.Severity)
	}
	kmh, _ := a.Detail["implied_kmh"].(float64)
	if kmh <= impossibleTravelMaxKMH {
		t.Errorf("implied_kmh = %v want > %v", kmh, impossibleTravelMaxKMH)
	}
	km, _ := a.Detail["distance_km"].(float64)
	if km < 9000 {
		t.Errorf("distance_km = %v want a transoceanic distance", km)
	}
}

func TestImpossibleTravelBenignPlausibleSpeed(t *testing.T) {
	conn := testDB(t)
	dev := "dev_fly"
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locLondon}
	// NYC → London (~5,570 km) over 8 hours → ~700 km/h — a normal flight.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-9*time.Hour))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, geo)
	if got := alertsOfKind(t, conn, KindImpossibleTravel); len(got) != 0 {
		t.Fatalf("plausible flight produced %d impossible_travel alerts want 0", len(got))
	}
}

func TestImpossibleTravelSkipsUnresolvable(t *testing.T) {
	conn := testDB(t)
	dev := "dev_priv"
	// Only the first IP geolocates; the second is private/unknown → skip.
	geo := fakeGeo{"203.0.113.10": locNYC}
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "10.0.0.5", fixedNow.Add(-10*time.Minute))

	sweep(t, conn, geo)
	if got := alertsOfKind(t, conn, KindImpossibleTravel); len(got) != 0 {
		t.Fatalf("unresolvable IP produced %d impossible_travel alerts want 0", len(got))
	}
}

// TestImpossibleTravelSkipsSubSkewDelta is HIGH-6/HIGH-7: two distant connects
// closer in time than clockSkewTolerance must NOT alert — the Δt is dominated by
// inter-node clock skew, and the old code clamped a zero/near-zero Δt to a huge
// speed, fabricating a guaranteed CRITICAL from mere simultaneity.
func TestImpossibleTravelSkipsSubSkewDelta(t *testing.T) {
	conn := testDB(t)
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locTokyo}

	// Identical timestamps (Δt == 0): pure simultaneity / skew, never a clamp.
	devZero := "dev_skew_zero"
	seedEvent(t, conn, devZero, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, devZero, "node_b", "connect", "198.51.100.20", fixedNow.Add(-30*time.Minute))

	// Δt below clockSkewTolerance (10s < 60s): indistinguishable from drift.
	devSub := "dev_skew_sub"
	seedEvent(t, conn, devSub, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, devSub, "node_b", "connect", "198.51.100.20", fixedNow.Add(-30*time.Minute).Add(10*time.Second))

	sweep(t, conn, geo)
	if got := alertsOfKind(t, conn, KindImpossibleTravel); len(got) != 0 {
		t.Fatalf("sub-skew Δt produced %d impossible_travel alerts want 0 (skew/simultaneity, not travel)", len(got))
	}
}

// TestImpossibleTravelFiresBeyondSkew confirms a genuinely-too-fast hop still
// fires once Δt clears the skew tolerance: even charging the worst-case drift
// against the elapsed time (Δt − clockSkewTolerance), the implied speed exceeds
// the threshold.
func TestImpossibleTravelFiresBeyondSkew(t *testing.T) {
	conn := testDB(t)
	dev := "dev_fast_beyond_skew"
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locTokyo}
	// NYC→Tokyo (~10,800 km) just 5 minutes apart. Δt (300s) is well above the
	// 60s skew bound; over the lower-bound 240s the speed is still ~162,000 km/h.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-10*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-5*time.Minute))

	sweep(t, conn, geo)
	got := alertsOfKind(t, conn, KindImpossibleTravel)
	if len(got) != 1 {
		t.Fatalf("genuinely-too-fast hop beyond skew: got %d alerts want 1", len(got))
	}
	kmh, _ := got[0].Detail["implied_kmh"].(float64)
	if kmh <= impossibleTravelMaxKMH {
		t.Errorf("implied_kmh = %v want > %v (computed over the lower-bound elapsed time)", kmh, impossibleTravelMaxKMH)
	}
}

// --- concurrent_sessions --------------------------------------------------

func TestConcurrentSessionsFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_concurrent"
	// Connect on A, then connect on B before A disconnects → overlap on 2 nodes.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-20*time.Minute))
	seedEvent(t, conn, dev, "node_a", "disconnect", "203.0.113.10", fixedNow.Add(-10*time.Minute))

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindConcurrentSessions)
	if len(got) != 1 {
		t.Fatalf("concurrent_sessions: got %d want 1", len(got))
	}
	if got[0].Severity != SeverityWarning {
		t.Errorf("severity = %q want warning", got[0].Severity)
	}
	nodes, _ := got[0].Detail["nodes"].([]any)
	if len(nodes) != 2 {
		t.Errorf("nodes = %v want 2", got[0].Detail["nodes"])
	}
}

func TestConcurrentSessionsBenignSequential(t *testing.T) {
	conn := testDB(t)
	dev := "dev_seq"
	// Connect A, disconnect A, THEN connect B — no overlap.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, dev, "node_a", "disconnect", "203.0.113.10", fixedNow.Add(-20*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-10*time.Minute))
	seedEvent(t, conn, dev, "node_b", "disconnect", "198.51.100.20", fixedNow.Add(-5*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindConcurrentSessions); len(got) != 0 {
		t.Fatalf("sequential sessions produced %d concurrent alerts want 0", len(got))
	}
}

// TestConcurrentSessionsIgnoresStaleDanglingConnect is MED-10: a connect whose
// disconnect was dropped must not be believed active to `now`, or one stale
// connect overlaps every later session forever. Here an old connect on A (its
// disconnect lost) is capped at connect+maxOpenSessionAge, which ends well
// before a clean, separate session on B → no fabricated overlap.
func TestConcurrentSessionsIgnoresStaleDanglingConnect(t *testing.T) {
	conn := testDB(t)
	dev := "dev_dangling"
	// Dangling connect on A ~3h ago, no disconnect. Capped at +30m, so it is
	// treated as closed ~2.5h before now.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-3*time.Hour))
	// A clean, well-separated session on B much later.
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-20*time.Minute))
	seedEvent(t, conn, dev, "node_b", "disconnect", "198.51.100.20", fixedNow.Add(-10*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindConcurrentSessions); len(got) != 0 {
		t.Fatalf("stale dangling connect fabricated %d concurrent alerts want 0", len(got))
	}
}

// TestConcurrentSessionsRecentOpenStillCatchesOverlap confirms the cap does not
// blind the rule to a real overlap: two recent open connects (within
// maxOpenSessionAge of now) on different nodes still overlap and fire.
func TestConcurrentSessionsRecentOpenStillCatchesOverlap(t *testing.T) {
	conn := testDB(t)
	dev := "dev_recent_open"
	// Both connects are recent and still open; their caps reach up to now, so
	// they genuinely overlap on two nodes — a real second session.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-15*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-10*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindConcurrentSessions); len(got) != 1 {
		t.Fatalf("real overlap of two recent open sessions: got %d alerts want 1", len(got))
	}
}

// TestConcurrentSessionsIgnoresSubSkewOverlap is MED-10/HIGH-7: an overlap
// shorter than clockSkewTolerance is indistinguishable from two nodes' clocks
// disagreeing and must not fire.
func TestConcurrentSessionsIgnoresSubSkewOverlap(t *testing.T) {
	conn := testDB(t)
	dev := "dev_subskew_overlap"
	// Session A: connect then disconnect. Session B connects 10s before A's
	// disconnect → a 10s overlap, below the 60s skew tolerance.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-20*time.Minute).Add(-10*time.Second))
	seedEvent(t, conn, dev, "node_a", "disconnect", "203.0.113.10", fixedNow.Add(-20*time.Minute))
	seedEvent(t, conn, dev, "node_b", "disconnect", "198.51.100.20", fixedNow.Add(-15*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindConcurrentSessions); len(got) != 0 {
		t.Fatalf("sub-skew overlap produced %d concurrent alerts want 0", len(got))
	}
}

// --- new_geo --------------------------------------------------------------

func TestNewGeoFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_geo"
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locLondon}
	// Historical connect from the US (well before the window).
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-72*time.Hour))
	// New connect from GB inside the window — a never-before country.
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, geo)

	got := alertsOfKind(t, conn, KindNewGeo)
	if len(got) != 1 {
		t.Fatalf("new_geo: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityInfo {
		t.Errorf("severity = %q want info", a.Severity)
	}
	if a.Detail["country"] != "GB" {
		t.Errorf("country = %v want GB", a.Detail["country"])
	}
}

func TestNewGeoBenignKnownCountry(t *testing.T) {
	conn := testDB(t)
	dev := "dev_home"
	geo := fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locNewark}
	// History in the US; new connect from a DIFFERENT US city — same country, no alert.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-72*time.Hour))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, geo)
	if got := alertsOfKind(t, conn, KindNewGeo); len(got) != 0 {
		t.Fatalf("same-country connect produced %d new_geo alerts want 0", len(got))
	}
}

// --- dedup ----------------------------------------------------------------

func TestDedupRefreshesNotDuplicates(t *testing.T) {
	conn := testDB(t)
	dev := "dev_persist"
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-9*time.Minute))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-5*time.Minute))

	// First sweep opens the alert.
	fresh1 := sweep(t, conn, nil)
	if !containsKind(fresh1, KindLeakedProfile) {
		t.Fatalf("first sweep did not open a leaked_profile alert")
	}

	// A later third IP keeps the condition live; second sweep must REFRESH,
	// not insert a duplicate.
	seedEvent(t, conn, dev, "node_c", "connect", "192.0.2.30", fixedNow.Add(-2*time.Minute))
	fresh2, err := Sweep(context.Background(), conn, nil, fixedNow.Add(1*time.Minute), DefaultWindow)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}

	got := alertsOfKind(t, conn, KindLeakedProfile)
	if len(got) != 1 {
		t.Fatalf("dedup: got %d leaked_profile alerts after two sweeps want 1", len(got))
	}
	if containsKind(fresh2, KindLeakedProfile) {
		t.Errorf("second sweep reported the refreshed alert as fresh; should be silent")
	}
	// The refreshed alert merged the third IP into its evidence.
	if len(got[0].SourceIPs) != 3 {
		t.Errorf("refreshed source_ips = %v want 3 merged", got[0].SourceIPs)
	}
}

// --- device_id IS NOT NULL filter ----------------------------------------

func TestInfraLinksNeverAlert(t *testing.T) {
	conn := testDB(t)
	// NULL device_id = node-to-node cascade inner-link. Even a textbook
	// leaked-profile pattern (2 IPs in 10m) must produce NO alerts.
	seedEvent(t, conn, "", "node_a", "connect", "203.0.113.10", fixedNow.Add(-9*time.Minute))
	seedEvent(t, conn, "", "node_b", "connect", "198.51.100.20", fixedNow.Add(-5*time.Minute))

	fresh := sweep(t, conn, fakeGeo{"203.0.113.10": locNYC, "198.51.100.20": locTokyo})
	if len(fresh) != 0 {
		t.Fatalf("infra links produced %d alerts want 0", len(fresh))
	}
	all, err := Query(context.Background(), conn, Filter{Limit: MaxLimit})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("infra links produced %d total alerts want 0", len(all))
	}
}

// --- backend warning ------------------------------------------------------

func TestBackendWarningOnSQLite(t *testing.T) {
	if w := BackendWarning(BackendSQLite); w == "" {
		t.Error("expected a backend warning on SQLite")
	}
	if w := BackendWarning(""); w == "" {
		t.Error("expected a backend warning when backend is unset (defaults to SQLite)")
	}
	if !BackendIsSQLite(BackendSQLite) || !BackendIsSQLite("") {
		t.Error("BackendIsSQLite should be true for sqlite/empty")
	}
}

func TestBackendWarningSilentOnPostgres(t *testing.T) {
	if w := BackendWarning(BackendPostgres); w != "" {
		t.Errorf("expected no backend warning on Postgres, got %q", w)
	}
	if BackendIsSQLite(BackendPostgres) {
		t.Error("BackendIsSQLite should be false for postgres")
	}
}

// containsKind reports whether any alert in the slice is of the given kind.
func containsKind(alerts []Alert, kind string) bool {
	for _, a := range alerts {
		if a.Kind == kind {
			return true
		}
	}
	return false
}
