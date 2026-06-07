// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/idgen"
)

// seedDevice inserts a device row with the given status, so the
// revoked_profile_active rule can look it up. user_id matches seedEvent's usr_1.
func seedDevice(t *testing.T, conn *sql.DB, deviceID, status string) {
	t.Helper()
	if _, err := account.CreateUser(context.Background(), conn, account.User{
		ID: "usr_1", Name: "u", Role: account.RoleUser,
	}); err != nil {
		// A duplicate user across helpers is fine; only fail on a real error.
		if !isDupUser(err) {
			t.Fatalf("seed user: %v", err)
		}
	}
	if _, err := account.CreateDevice(context.Background(), conn, account.Device{
		ID: deviceID, UserID: "usr_1", Name: deviceID, Status: status,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
}

// isDupUser reports whether err is a unique-constraint violation from inserting
// the shared test user twice (benign across helpers in one test).
func isDupUser(err error) bool {
	return err != nil && (containsAny(err.Error(), "UNIQUE", "duplicate", "constraint"))
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// seedAuthFailure inserts one auth.login_failed audit_log row from a source IP
// with an attempted username, at a given time.
func seedAuthFailure(t *testing.T, conn *sql.DB, sourceIP, username string, at time.Time) {
	t.Helper()
	detail := `{"username":"` + username + `"}`
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO audit_log
		(id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		idgen.New("aud"), at.UTC(), "anonymous", "session", "auth.login_failed",
		"user", "", sourceIP, detail, "error", "bad credentials")
	if err != nil {
		t.Fatalf("seed auth failure: %v", err)
	}
}

// seedNode inserts a node with the given status (via CreateNode + SetNodeStatus
// when the target status is not a creation default).
func seedNode(t *testing.T, conn *sql.DB, nodeID, name, status string) {
	t.Helper()
	_, err := fleet.CreateNode(context.Background(), conn, fleet.Node{
		ID: nodeID, Name: name, Region: "nyc",
	})
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := fleet.SetNodeStatus(context.Background(), conn, nodeID, status); err != nil {
		t.Fatalf("set node status: %v", err)
	}
}

// --- revoked_profile_active ------------------------------------------------

func TestRevokedProfileActiveFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_revoked"
	seedDevice(t, conn, dev, account.StatusDisabled)
	// A revoked device still connecting inside the window.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindRevokedProfileActive)
	if len(got) != 1 {
		t.Fatalf("revoked_profile_active: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %q want critical", a.Severity)
	}
	if a.DeviceID != dev {
		t.Errorf("device = %q want %q", a.DeviceID, dev)
	}
	if a.Detail["device_status"] != account.StatusDisabled {
		t.Errorf("device_status = %v want %q", a.Detail["device_status"], account.StatusDisabled)
	}
	if len(a.SourceIPs) != 1 || a.SourceIPs[0] != "203.0.113.10" {
		t.Errorf("source_ips = %v want [203.0.113.10]", a.SourceIPs)
	}
}

func TestRevokedProfileActiveBenignActiveDevice(t *testing.T) {
	conn := testDB(t)
	dev := "dev_active"
	seedDevice(t, conn, dev, account.StatusActive)
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-30*time.Minute))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindRevokedProfileActive); len(got) != 0 {
		t.Fatalf("active device produced %d revoked_profile_active alerts want 0", len(got))
	}
}

// --- auth_failure_spike ----------------------------------------------------

func TestAuthFailureSpikeFires(t *testing.T) {
	conn := testDB(t)
	ip := "203.0.113.66"
	// 5 failed logins within ~5 minutes from one IP — a spike.
	for i := 0; i < authFailureThreshold; i++ {
		seedAuthFailure(t, conn, ip, "admin", fixedNow.Add(time.Duration(-9+i)*time.Minute))
	}

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindAuthFailureSpike)
	if len(got) != 1 {
		t.Fatalf("auth_failure_spike: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityWarning {
		t.Errorf("severity = %q want warning", a.Severity)
	}
	if a.DeviceID != "" {
		t.Errorf("device = %q want empty (IP-scoped)", a.DeviceID)
	}
	if len(a.SourceIPs) != 1 || a.SourceIPs[0] != ip {
		t.Errorf("source_ips = %v want [%s]", a.SourceIPs, ip)
	}
	cnt, _ := a.Detail["failure_count"].(float64)
	if int(cnt) < authFailureThreshold {
		t.Errorf("failure_count = %v want >= %d", a.Detail["failure_count"], authFailureThreshold)
	}
	users, _ := a.Detail["attempted_usernames"].([]any)
	if len(users) != 1 || users[0] != "admin" {
		t.Errorf("attempted_usernames = %v want [admin]", a.Detail["attempted_usernames"])
	}
}

func TestAuthFailureSpikeBenignBelowThreshold(t *testing.T) {
	conn := testDB(t)
	ip := "203.0.113.77"
	// Only 3 failures — under the threshold.
	for i := 0; i < authFailureThreshold-2; i++ {
		seedAuthFailure(t, conn, ip, "root", fixedNow.Add(time.Duration(-9+i)*time.Minute))
	}

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindAuthFailureSpike); len(got) != 0 {
		t.Fatalf("below-threshold failures produced %d spike alerts want 0", len(got))
	}
}

func TestAuthFailureSpikeBenignSpreadOut(t *testing.T) {
	conn := testDB(t)
	ip := "203.0.113.88"
	// 5 failures but ~3h apart each — never 5 inside a 10m window.
	for i := 0; i < authFailureThreshold; i++ {
		seedAuthFailure(t, conn, ip, "admin", fixedNow.Add(time.Duration(-20+3*i)*time.Hour))
	}

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindAuthFailureSpike); len(got) != 0 {
		t.Fatalf("spread-out failures produced %d spike alerts want 0", len(got))
	}
}

// --- dormant_then_active ---------------------------------------------------

func TestDormantThenActiveFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_dormant"
	// A connect 40 days ago (outside the window), then a fresh connect now.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-40*24*time.Hour))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindDormantThenActive)
	if len(got) != 1 {
		t.Fatalf("dormant_then_active: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityInfo {
		t.Errorf("severity = %q want info", a.Severity)
	}
	days, _ := a.Detail["dormant_days"].(float64)
	if int(days) < 30 {
		t.Errorf("dormant_days = %v want >= 30", a.Detail["dormant_days"])
	}
}

func TestDormantThenActiveBenignRecentlyActive(t *testing.T) {
	conn := testDB(t)
	dev := "dev_regular"
	// Prior connect only 5 days ago — not dormant.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-5*24*time.Hour))
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindDormantThenActive); len(got) != 0 {
		t.Fatalf("recently-active device produced %d dormant alerts want 0", len(got))
	}
}

func TestDormantThenActiveBenignFirstEver(t *testing.T) {
	conn := testDB(t)
	dev := "dev_brandnew"
	// Only one connect ever (inside the window) — no prior, so no dormancy.
	seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindDormantThenActive); len(got) != 0 {
		t.Fatalf("first-ever connect produced %d dormant alerts want 0", len(got))
	}
}

// --- off_hours_access ------------------------------------------------------

// seedHourlyHistory seeds `perDay` connects/day at the given UTC hour across
// `days` distinct days (all before the window), building a device's baseline.
func seedHourlyHistory(t *testing.T, conn *sql.DB, dev string, hour, days, perDay int) {
	t.Helper()
	for d := 1; d <= days; d++ {
		base := fixedNow.Add(-time.Duration(d) * 24 * time.Hour)
		day := time.Date(base.Year(), base.Month(), base.Day(), hour, 0, 0, 0, time.UTC)
		for p := 0; p < perDay; p++ {
			seedEvent(t, conn, dev, "node_a", "connect", "203.0.113.10", day.Add(time.Duration(p)*time.Minute))
		}
	}
}

func TestOffHoursAccessFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_offhours"
	// Baseline: connects at 09:00 UTC across 10 days, 3/day = 30 connects.
	seedHourlyHistory(t, conn, dev, 9, 10, 3)
	// A fresh connect at 03:00 UTC inside the window — never-used hour.
	odd := time.Date(fixedNow.Year(), fixedNow.Month(), fixedNow.Day(), 3, 0, 0, 0, time.UTC)
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", odd)

	// Sweep with a window wide enough to include the 03:00 connect today.
	if _, err := Sweep(context.Background(), conn, nil, fixedNow, DefaultWindow); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	got := alertsOfKind(t, conn, KindOffHoursAccess)
	if len(got) != 1 {
		t.Fatalf("off_hours_access: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityInfo {
		t.Errorf("severity = %q want info", a.Severity)
	}
	if h, _ := a.Detail["hour_utc"].(float64); int(h) != 3 {
		t.Errorf("hour_utc = %v want 3", a.Detail["hour_utc"])
	}
}

func TestOffHoursAccessBelowMinHistoryDoesNotFire(t *testing.T) {
	conn := testDB(t)
	dev := "dev_thin"
	// Only 6 prior connects over 2 days — below offHoursMinConnects/Days.
	seedHourlyHistory(t, conn, dev, 9, 2, 3)
	odd := time.Date(fixedNow.Year(), fixedNow.Month(), fixedNow.Day(), 3, 0, 0, 0, time.UTC)
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", odd)

	if _, err := Sweep(context.Background(), conn, nil, fixedNow, DefaultWindow); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := alertsOfKind(t, conn, KindOffHoursAccess); len(got) != 0 {
		t.Fatalf("thin-history device produced %d off_hours alerts want 0", len(got))
	}
}

func TestOffHoursAccessBenignTypicalHour(t *testing.T) {
	conn := testDB(t)
	dev := "dev_ontime"
	// Strong 09:00 baseline; the window connect is ALSO at 09:00 — normal.
	seedHourlyHistory(t, conn, dev, 9, 10, 3)
	onTime := time.Date(fixedNow.Year(), fixedNow.Month(), fixedNow.Day(), 9, 30, 0, 0, time.UTC)
	seedEvent(t, conn, dev, "node_b", "connect", "198.51.100.20", onTime)

	if _, err := Sweep(context.Background(), conn, nil, fixedNow, DefaultWindow); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := alertsOfKind(t, conn, KindOffHoursAccess); len(got) != 0 {
		t.Fatalf("typical-hour connect produced %d off_hours alerts want 0", len(got))
	}
}

// --- fleet_health ----------------------------------------------------------

func TestFleetHealthUnreachableFires(t *testing.T) {
	conn := testDB(t)
	seedNode(t, conn, "node_unreach", "ams-1", fleet.StatusUnreachable)

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindFleetHealth)
	if len(got) != 1 {
		t.Fatalf("fleet_health: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityWarning {
		t.Errorf("severity = %q want warning", a.Severity)
	}
	if a.NodeID != "node_unreach" {
		t.Errorf("node_id = %q want node_unreach", a.NodeID)
	}
	if a.DeviceID != "" {
		t.Errorf("device_id = %q want empty (node-scoped)", a.DeviceID)
	}
	if a.Detail["node_status"] != fleet.StatusUnreachable {
		t.Errorf("node_status = %v want %q", a.Detail["node_status"], fleet.StatusUnreachable)
	}
}

func TestFleetHealthErrorIsCritical(t *testing.T) {
	conn := testDB(t)
	seedNode(t, conn, "node_err", "sfo-1", fleet.StatusError)

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindFleetHealth)
	if len(got) != 1 {
		t.Fatalf("fleet_health: got %d want 1", len(got))
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("severity = %q want critical", got[0].Severity)
	}
}

func TestFleetHealthAutoResolvesOnRecovery(t *testing.T) {
	conn := testDB(t)
	node := "node_flap"
	seedNode(t, conn, node, "lon-1", fleet.StatusUnreachable)

	// First sweep opens the alert.
	sweep(t, conn, nil)
	open := openAlertsOfKind(t, conn, KindFleetHealth)
	if len(open) != 1 {
		t.Fatalf("after first sweep: %d open fleet_health alerts want 1", len(open))
	}

	// Node recovers; a second sweep must auto-resolve the open alert.
	if err := fleet.SetNodeStatus(context.Background(), conn, node, fleet.StatusActive); err != nil {
		t.Fatalf("recover node: %v", err)
	}
	if _, err := Sweep(context.Background(), conn, nil, fixedNow.Add(time.Minute), DefaultWindow); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if open := openAlertsOfKind(t, conn, KindFleetHealth); len(open) != 0 {
		t.Fatalf("after recovery: %d open fleet_health alerts want 0 (auto-resolve)", len(open))
	}
	// The alert still exists, now resolved.
	resolved, err := Query(context.Background(), conn, Filter{Kind: KindFleetHealth, Status: StatusResolved, Limit: MaxLimit})
	if err != nil {
		t.Fatalf("query resolved: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("resolved fleet_health alerts = %d want 1", len(resolved))
	}
}

func TestFleetHealthBenignActiveNode(t *testing.T) {
	conn := testDB(t)
	seedNode(t, conn, "node_ok", "fra-1", fleet.StatusActive)

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindFleetHealth); len(got) != 0 {
		t.Fatalf("active node produced %d fleet_health alerts want 0", len(got))
	}
}

// --- dedup across rules ----------------------------------------------------

func TestTier2DedupRefreshesNotDuplicates(t *testing.T) {
	conn := testDB(t)
	seedNode(t, conn, "node_persist", "ams-2", fleet.StatusUnreachable)

	sweep(t, conn, nil)
	if _, err := Sweep(context.Background(), conn, nil, fixedNow.Add(time.Minute), DefaultWindow); err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if got := openAlertsOfKind(t, conn, KindFleetHealth); len(got) != 1 {
		t.Fatalf("two sweeps of a persistent unreachable node produced %d open alerts want 1", len(got))
	}
}

// openAlertsOfKind returns the OPEN alerts of a given kind.
func openAlertsOfKind(t *testing.T, conn *sql.DB, kind string) []Alert {
	t.Helper()
	all, err := Query(context.Background(), conn, Filter{Kind: kind, Status: StatusOpen, Limit: MaxLimit})
	if err != nil {
		t.Fatalf("query open %s: %v", kind, err)
	}
	return all
}
