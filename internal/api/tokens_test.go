// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

// bearerReq issues a request carrying an Authorization: Bearer token (no cookie
// jar — token auth is independent of sessions).
func bearerReq(t *testing.T, ts *httptest.Server, method, path, secret, body string) *http.Response {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// TestBearerAdminTokenPassesMutation: an admin-scoped bearer token may perform a
// mutation (POST /api/users).
func TestBearerAdminTokenPassesMutation(t *testing.T) {
	ts, _, conn := setup(t)
	secret, _, err := authn.Create(context.Background(), conn, "ci-admin", authn.ScopeAdmin, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	resp := bearerReq(t, ts, http.MethodPost, "/api/users", secret,
		`{"name":"T","email":"t@example.com"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin token mutation: status %d want 201", resp.StatusCode)
	}
}

// TestReadonlyTokenBlockedFromMutation: a readonly token is allowed a GET but
// 403'd on a mutation.
func TestReadonlyTokenBlockedFromMutation(t *testing.T) {
	ts, _, conn := setup(t)
	secret, _, err := authn.Create(context.Background(), conn, "ci-ro", authn.ScopeReadonly, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	// A GET is allowed.
	getResp := bearerReq(t, ts, http.MethodGet, "/api/nodes", secret, "")
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("readonly GET: status %d want 200", getResp.StatusCode)
	}

	// A mutation is forbidden.
	postResp := bearerReq(t, ts, http.MethodPost, "/api/users", secret,
		`{"name":"T","email":"t@example.com"}`)
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusForbidden {
		t.Errorf("readonly mutation: status %d want 403", postResp.StatusCode)
	}
}

// TestMonitorTokenScope: a monitor token reads (and the events stream) but is
// still blocked from mutations.
func TestMonitorTokenScope(t *testing.T) {
	ts, _, conn := setup(t)
	secret, _, err := authn.Create(context.Background(), conn, "ci-mon", authn.ScopeMonitor, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	getResp := bearerReq(t, ts, http.MethodGet, "/api/nodes", secret, "")
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("monitor GET: status %d want 200", getResp.StatusCode)
	}
	postResp := bearerReq(t, ts, http.MethodPost, "/api/users", secret, `{"name":"T","email":"t@example.com"}`)
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusForbidden {
		t.Errorf("monitor mutation: status %d want 403", postResp.StatusCode)
	}
}

// TestNoOrInvalidTokenUnauthorized: a missing token is 401; a malformed bearer
// secret is 401.
func TestNoOrInvalidTokenUnauthorized(t *testing.T) {
	ts, _, _ := setup(t)

	// No credentials at all.
	none := bearerReq(t, ts, http.MethodGet, "/api/nodes", "", "")
	none.Body.Close()
	if none.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status %d want 401", none.StatusCode)
	}

	// A well-formed-but-unknown bearer token.
	bad := bearerReq(t, ts, http.MethodGet, "/api/nodes", "cox_adm_unknown-secret", "")
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("invalid token: status %d want 401", bad.StatusCode)
	}
}

// TestRevokedTokenUnauthorized: a revoked token is rejected at the middleware.
func TestRevokedTokenUnauthorized(t *testing.T) {
	ts, _, conn := setup(t)
	secret, rec, err := authn.Create(context.Background(), conn, "ci", authn.ScopeAdmin, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if err := authn.Revoke(context.Background(), conn, rec.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	resp := bearerReq(t, ts, http.MethodGet, "/api/nodes", secret, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token: status %d want 401", resp.StatusCode)
	}
}

// TestTokenManagementRoutes: create → list → revoke over the admin API, and the
// secret is returned exactly once on create.
func TestTokenManagementRoutes(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	createResp, err := client.Post(ts.URL+"/api/tokens", "application/json",
		strings.NewReader(`{"name":"dashboard","scope":"monitor"}`))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	var created struct {
		ID     string `json:"id"`
		Scope  string `json:"scope"`
		Secret string `json:"secret"`
	}
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: status %d", createResp.StatusCode)
	}
	if created.Scope != "monitor" || !strings.HasPrefix(created.Secret, "cox_mon_") {
		t.Errorf("created token: %+v", created)
	}

	// The created token authenticates.
	authResp := bearerReq(t, ts, http.MethodGet, "/api/nodes", created.Secret, "")
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Errorf("new token GET: status %d want 200", authResp.StatusCode)
	}

	// List shows the token (without a secret field).
	listResp, err := client.Get(ts.URL + "/api/tokens")
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	var tokens []map[string]any
	json.NewDecoder(listResp.Body).Decode(&tokens) //nolint:errcheck
	listResp.Body.Close()
	if len(tokens) != 1 {
		t.Fatalf("list: got %d want 1", len(tokens))
	}
	if _, leaked := tokens[0]["secret"]; leaked {
		t.Error("token listing must not contain a secret")
	}

	// Revoke, then the token no longer authenticates.
	if code := deleteReq(t, client, ts.URL+"/api/tokens/"+created.ID); code != http.StatusNoContent {
		t.Errorf("revoke token: status %d want 204", code)
	}
	gone := bearerReq(t, ts, http.MethodGet, "/api/nodes", created.Secret, "")
	gone.Body.Close()
	if gone.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token GET: status %d want 401", gone.StatusCode)
	}
}

// TestMutationWritesAuditRow: a successful session mutation writes an audit row
// with the right action, actor, and result=ok.
func TestMutationWritesAuditRow(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)

	resp, err := client.Post(ts.URL+"/api/users", "application/json",
		strings.NewReader(`{"name":"Audited","email":"audited@example.com"}`))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: status %d", resp.StatusCode)
	}

	records, err := audit.Query(context.Background(), conn, audit.Filter{Action: "user.add"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("audit rows: got %d want 1", len(records))
	}
	r := records[0]
	if r.Result != audit.ResultOK {
		t.Errorf("result: got %q want ok", r.Result)
	}
	if r.ActorKind != audit.KindSession {
		t.Errorf("actor_kind: got %q want session", r.ActorKind)
	}
	if r.Actor == "" {
		t.Error("audit row should record the actor")
	}
	if r.TargetID == "" {
		t.Error("audit row should record the created user id")
	}
}

// failingPaths is a PathCoordinator whose mutations always error — to exercise
// the handlers' audited failure branch end-to-end.
type failingPaths struct{}

func (failingPaths) ProvisionPath(context.Context, string) (fleet.Path, error) {
	return fleet.Path{}, errors.New("provision boom")
}
func (failingPaths) DeprovisionPath(context.Context, string) error {
	return errors.New("deprovision boom")
}
func (failingPaths) BindDeviceToPath(context.Context, string, string) error {
	return errors.New("bind boom")
}
func (failingPaths) ClearDevicePath(context.Context, string) error { return errors.New("clear boom") }

// TestFailedMutationWritesErrorRow: a mutation whose handler fails writes an
// audit row with result=error and the error message, driven end-to-end through
// the HTTP handler (a failing path coordinator forces the bind to error).
func TestFailedMutationWritesErrorRow(t *testing.T) {
	conn := newTestDB(t)
	srv := NewServer("", conn, live.NewHub(), provision.Options{
		VPNSubnet: "10.86.0.0/16", PortMin: 2000, PortMax: 60000,
	}, nil, failingPaths{}, nil, "")
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	// Drive the bind handler with an admin token; the coordinator errors → 502,
	// and the handler must have written a result=error audit row.
	secret, _, err := authn.Create(context.Background(), conn, "ci", authn.ScopeAdmin, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	resp := bearerReq(t, ts, http.MethodPost, "/api/devices/dev_x/bind", secret, `{"path_id":"pth_x"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("bind: status %d want 502", resp.StatusCode)
	}

	records, err := audit.Query(context.Background(), conn, audit.Filter{Action: "path.bind"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("audit rows: got %d want 1", len(records))
	}
	if records[0].Result != audit.ResultError || records[0].Error == "" {
		t.Errorf("error row: %+v", records[0])
	}
	if records[0].ActorKind != audit.KindToken {
		t.Errorf("actor_kind: got %q want token", records[0].ActorKind)
	}
}
