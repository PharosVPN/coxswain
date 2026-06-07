// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/idgen"
)

// seedAlert inserts one open alert row directly and returns its id.
func seedAlert(t *testing.T, conn *sql.DB, kind, severity, deviceID string) string {
	t.Helper()
	id := idgen.New("alr")
	now := time.Now().UTC()
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO alerts
		(id, at, kind, severity, device_id, user_id, node_id, source_ips, detail, status, dedup_key, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
		id, now, kind, severity, deviceID, "usr_1", "node_a",
		`["203.0.113.10"]`, `{"distinct_ips":2}`, kind+":"+deviceID, now, now)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return id
}

// TestAlertsListEnvelope: an admin reads /api/alerts and gets the alert plus the
// SQLite backend warning in the envelope.
func TestAlertsListEnvelope(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	seedAlert(t, conn, analytics.KindLeakedProfile, analytics.SeverityWarning, "dev_1")

	resp, err := client.Get(ts.URL + "/api/alerts")
	if err != nil {
		t.Fatalf("get alerts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alerts: status %d want 200", resp.StatusCode)
	}
	var env alertsEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Alerts) != 1 {
		t.Fatalf("alerts: got %d want 1", len(env.Alerts))
	}
	if env.Alerts[0].Kind != analytics.KindLeakedProfile {
		t.Errorf("kind = %q want leaked_profile", env.Alerts[0].Kind)
	}
	// The test server defaults to the SQLite backend → the warning is present.
	if env.Backend != "sqlite" {
		t.Errorf("backend = %q want sqlite", env.Backend)
	}
	if env.BackendWarning == "" {
		t.Error("expected a backend_warning on SQLite")
	}
}

// TestAlertsFilters: status/kind filters narrow the result.
func TestAlertsFilters(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	seedAlert(t, conn, analytics.KindLeakedProfile, analytics.SeverityWarning, "dev_1")
	seedAlert(t, conn, analytics.KindNewGeo, analytics.SeverityInfo, "dev_2")

	resp, err := client.Get(ts.URL + "/api/alerts?kind=" + analytics.KindNewGeo)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var env alertsEnvelope
	json.NewDecoder(resp.Body).Decode(&env) //nolint:errcheck
	if len(env.Alerts) != 1 || env.Alerts[0].Kind != analytics.KindNewGeo {
		t.Fatalf("kind filter: got %d alerts %v", len(env.Alerts), env.Alerts)
	}
}

// TestAlertsScope: /api/alerts is monitor-scoped — readonly 403, monitor 200.
func TestAlertsScope(t *testing.T) {
	ts, _, conn := setup(t)

	ro, _, err := authn.Create(context.Background(), conn, "ro", authn.ScopeReadonly, 0, "test")
	if err != nil {
		t.Fatalf("create readonly: %v", err)
	}
	roResp := bearerReq(t, ts, http.MethodGet, "/api/alerts", ro, "")
	roResp.Body.Close()
	if roResp.StatusCode != http.StatusForbidden {
		t.Errorf("readonly /api/alerts: status %d want 403", roResp.StatusCode)
	}

	mon, _, err := authn.Create(context.Background(), conn, "mon", authn.ScopeMonitor, 0, "test")
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}
	monResp := bearerReq(t, ts, http.MethodGet, "/api/alerts", mon, "")
	monResp.Body.Close()
	if monResp.StatusCode != http.StatusOK {
		t.Errorf("monitor /api/alerts: status %d want 200", monResp.StatusCode)
	}
}

// TestAlertAckRequiresAdminAndAudits: a monitor token cannot ack; an admin token
// can, and the ack writes an audit row and flips the status.
func TestAlertAckRequiresAdminAndAudits(t *testing.T) {
	ts, _, conn := setup(t)
	id := seedAlert(t, conn, analytics.KindLeakedProfile, analytics.SeverityWarning, "dev_1")

	// A monitor token is 403'd on the ack mutation.
	mon, _, err := authn.Create(context.Background(), conn, "mon", authn.ScopeMonitor, 0, "test")
	if err != nil {
		t.Fatalf("create monitor: %v", err)
	}
	monResp := bearerReq(t, ts, http.MethodPost, "/api/alerts/"+id+"/ack", mon, "")
	monResp.Body.Close()
	if monResp.StatusCode != http.StatusForbidden {
		t.Fatalf("monitor ack: status %d want 403", monResp.StatusCode)
	}

	// An admin token acks successfully.
	adm, _, err := authn.Create(context.Background(), conn, "adm", authn.ScopeAdmin, 0, "test")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	admResp := bearerReq(t, ts, http.MethodPost, "/api/alerts/"+id+"/ack", adm, "")
	defer admResp.Body.Close()
	if admResp.StatusCode != http.StatusOK {
		t.Fatalf("admin ack: status %d want 200", admResp.StatusCode)
	}

	// The status flipped to acknowledged.
	got, err := analytics.Get(context.Background(), conn, id)
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.Status != analytics.StatusAcknowledged {
		t.Errorf("status = %q want acknowledged", got.Status)
	}

	// An audit row was written for alert.ack on this target.
	rows, err := audit.Query(context.Background(), conn, audit.Filter{Action: "alert.ack", TargetID: id})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(rows) == 0 {
		t.Error("expected an alert.ack audit row")
	}
}

// TestAlertResolve: resolve flips status to resolved (admin via session).
func TestAlertResolve(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)
	id := seedAlert(t, conn, analytics.KindImpossibleTravel, analytics.SeverityCritical, "dev_1")

	resp, err := client.Post(ts.URL+"/api/alerts/"+id+"/resolve", "application/json", nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve: status %d want 200", resp.StatusCode)
	}
	got, err := analytics.Get(context.Background(), conn, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != analytics.StatusResolved {
		t.Errorf("status = %q want resolved", got.Status)
	}
}

// TestAlertAckMissing: acking an unknown id is a 404.
func TestAlertAckMissing(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)
	resp, err := client.Post(ts.URL+"/api/alerts/alr_doesnotexist/ack", "application/json", nil)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ack missing: status %d want 404", resp.StatusCode)
	}
}

// TestAnalyticsStatusBackendWarning: the dedicated status endpoint reports the
// backend and warning, monitor-scoped.
func TestAnalyticsStatusBackendWarning(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)
	resp, err := client.Get(ts.URL + "/api/analytics/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Backend        string `json:"backend"`
		BackendWarning string `json:"backend_warning"`
	}
	json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck
	if body.Backend != "sqlite" || body.BackendWarning == "" {
		t.Errorf("status: backend=%q warning=%q want sqlite + non-empty", body.Backend, body.BackendWarning)
	}
}

// TestAlertsEnvelopeSilentOnPostgres: with the backend set to Postgres, the
// alerts envelope carries no backend_warning.
func TestAlertsEnvelopeSilentOnPostgres(t *testing.T) {
	ts, client, conn := setupWithBackend(t, "postgres")
	login(t, ts, client)
	seedAlert(t, conn, analytics.KindLeakedProfile, analytics.SeverityWarning, "dev_1")

	resp, err := client.Get(ts.URL + "/api/alerts")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var env alertsEnvelope
	json.NewDecoder(resp.Body).Decode(&env) //nolint:errcheck
	if env.Backend != "postgres" {
		t.Errorf("backend = %q want postgres", env.Backend)
	}
	if env.BackendWarning != "" {
		t.Errorf("backend_warning = %q want empty on Postgres", env.BackendWarning)
	}
}
