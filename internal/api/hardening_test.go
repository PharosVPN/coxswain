// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

// newHardeningServer builds a test server with a custom pusher/path coordinator
// and an optional behind_tls_proxy flag, returning the running httptest server,
// a cookie-jar client, and the DB.
func newHardeningServer(t *testing.T, pusher NodePusher, paths PathCoordinator, behindProxy bool) (*httptest.Server, *http.Client, *sql.DB) {
	t.Helper()
	conn := newTestDB(t)
	if err := auth.SyncConfigAdmin(context.Background(), conn, testAdminPassword); err != nil {
		t.Fatalf("SyncConfigAdmin: %v", err)
	}
	srv := NewServer("", conn, live.NewHub(), provision.Options{
		VPNSubnet: "10.86.0.0/16", PortMin: 2000, PortMax: 60000,
	}, nil, paths, nil, "")
	if pusher != nil {
		srv.SetNodePusher(pusher)
	}
	srv.SetBehindTLSProxy(behindProxy)
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}, conn
}

// sessionCookieFromLogin posts a login (with optional headers) and returns the
// cox_session cookie the server set, or nil if none was set.
func sessionCookieFromLogin(t *testing.T, ts *httptest.Server, client *http.Client, hdr map[string]string) *http.Cookie {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login", strings.NewReader(
		`{"username":"admin","password":"`+testAdminPassword+`"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

// TestLoginCookieSecureGating: over plain HTTP the session cookie is NOT Secure
// (so the SSH-tunnel-over-http-loopback workflow still works); with a trusted
// TLS proxy declared, X-Forwarded-Proto: https flips it Secure; an untrusted
// (default) deploy ignores the header so it can't be spoofed on.
func TestLoginCookieSecureGating(t *testing.T) {
	// Default deploy (no proxy trust), plain HTTP → not Secure.
	ts, client, _ := setup(t)
	if c := sessionCookieFromLogin(t, ts, client, nil); c == nil || c.Secure {
		t.Fatalf("plain http cookie should not be Secure: %+v", c)
	}
	// X-Forwarded-Proto is ignored unless behind_tls_proxy is set — a spoofed
	// header must not flip cookie security on a direct/loopback deploy.
	if c := sessionCookieFromLogin(t, ts, client, map[string]string{"X-Forwarded-Proto": "https"}); c == nil || c.Secure {
		t.Fatalf("spoofed X-Forwarded-Proto must not make the cookie Secure: %+v", c)
	}

	// With a trusted TLS proxy declared, forwarded https → Secure; http → not.
	tsP, clientP, _ := newHardeningServer(t, nil, nil, true)
	if c := sessionCookieFromLogin(t, tsP, clientP, map[string]string{"X-Forwarded-Proto": "https"}); c == nil || !c.Secure {
		t.Fatalf("behind-proxy + X-Forwarded-Proto:https should be Secure: %+v", c)
	}
	if c := sessionCookieFromLogin(t, tsP, clientP, map[string]string{"X-Forwarded-Proto": "http"}); c == nil || c.Secure {
		t.Fatalf("behind-proxy + X-Forwarded-Proto:http should not be Secure: %+v", c)
	}
}

// TestLoginFailedActorIsAnonymous: a failed login records a fixed anonymous
// actor (not the attacker-supplied username), with the submitted username in the
// structured detail blob (LOW-13).
func TestLoginFailedActorIsAnonymous(t *testing.T) {
	ts, client, conn := setup(t)
	resp, err := client.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"attacker\nINJECTED","password":"wrong"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	records, err := audit.Query(context.Background(), conn, audit.Filter{Action: "auth.login_failed"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("audit rows: got %d want 1", len(records))
	}
	r := records[0]
	if r.Actor != anonymousActor {
		t.Errorf("actor: got %q want %q (must not be the submitted username)", r.Actor, anonymousActor)
	}
	if r.Result != audit.ResultError {
		t.Errorf("result: got %q want error", r.Result)
	}
	if got := r.Detail["username"]; got != "attacker\nINJECTED" {
		t.Errorf("detail username: got %v want the submitted value", got)
	}
}

// TestLogoutWritesAuditRow: logging out records an auth.logout row (LOW-12).
func TestLogoutWritesAuditRow(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)

	resp, err := client.Post(ts.URL+"/api/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status %d want 204", resp.StatusCode)
	}

	records, err := audit.Query(context.Background(), conn, audit.Filter{Action: "auth.logout"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("auth.logout rows: got %d want 1", len(records))
	}
	if records[0].ActorKind != audit.KindSession {
		t.Errorf("actor_kind: got %q want session", records[0].ActorKind)
	}
}

// fakePushResult JSON-encodes the fields pushDetail extracts.
type fakePushResult struct {
	PushedRevision  int64 `json:"PushedRevision"`
	AppliedRevision int64 `json:"AppliedRevision"`
	AmneziaPeers    int   `json:"AmneziaPeers"`
	Reloaded        bool  `json:"Reloaded"`
}

// TestPushNodeWritesAuditRow: POST /api/nodes/{id}/push writes a node.push row
// (HIGH-2). A fake pusher stands in for the reconcile primitive.
func TestPushNodeWritesAuditRow(t *testing.T) {
	pusher := func(_ context.Context, _ string) (any, error) {
		return fakePushResult{PushedRevision: 7, AppliedRevision: 7, AmneziaPeers: 3, Reloaded: true}, nil
	}
	ts, client, conn := newHardeningServer(t, pusher, nil, false)
	login(t, ts, client)

	node, err := fleet.CreateNode(context.Background(), conn, fleet.Node{Name: "n1", Region: "eu"})
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}
	resp, err := client.Post(ts.URL+"/api/nodes/"+node.ID+"/push", "application/json", nil)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: status %d want 200", resp.StatusCode)
	}

	records, err := audit.Query(context.Background(), conn, audit.Filter{Action: "node.push"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("node.push rows: got %d want 1", len(records))
	}
	r := records[0]
	if r.TargetID != node.ID || r.Result != audit.ResultOK {
		t.Errorf("row: %+v", r)
	}
	if r.Detail["PushedRevision"] == nil {
		t.Errorf("detail should carry the push revision: %+v", r.Detail)
	}
}

// provisionOnlyCoordinator implements PathCoordinator with a ProvisionPath that
// just returns the stored path (the inner-link delivery is what we are not
// exercising — only the audit write on the API path).
type provisionOnlyCoordinator struct{ db *sql.DB }

func (c provisionOnlyCoordinator) ProvisionPath(ctx context.Context, pathID string) (fleet.Path, error) {
	return fleet.GetPath(ctx, c.db, pathID)
}
func (provisionOnlyCoordinator) DeprovisionPath(context.Context, string) error          { return nil }
func (provisionOnlyCoordinator) BindDeviceToPath(context.Context, string, string) error { return nil }
func (provisionOnlyCoordinator) ClearDevicePath(context.Context, string) error          { return nil }

// TestProvisionPathWritesAuditRow: POST /api/paths/{id}/provision writes a
// path.provision row (HIGH-3).
func TestProvisionPathWritesAuditRow(t *testing.T) {
	conn := newTestDB(t)
	if err := auth.SyncConfigAdmin(context.Background(), conn, testAdminPassword); err != nil {
		t.Fatalf("SyncConfigAdmin: %v", err)
	}

	ctx := context.Background()
	entry, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "entry", Region: "nyc1"})
	if err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	exit, err := fleet.CreateNode(ctx, conn, fleet.Node{Name: "exit", Region: "ams3"})
	if err != nil {
		t.Fatalf("seed exit: %v", err)
	}
	path, err := fleet.CreatePath(ctx, conn, "p", "", []string{entry.ID, exit.ID})
	if err != nil {
		t.Fatalf("seed path: %v", err)
	}

	srv := NewServer("", conn, live.NewHub(), provision.Options{
		VPNSubnet: "10.86.0.0/16", PortMin: 2000, PortMax: 60000,
	}, nil, provisionOnlyCoordinator{db: conn}, nil, "")
	ts2 := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts2.Close)
	jar, _ := cookiejar.New(nil)
	client2 := &http.Client{Jar: jar}
	login(t, ts2, client2)

	resp, err := client2.Post(ts2.URL+"/api/paths/"+path.ID+"/provision", "application/json", nil)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("provision: status %d want 200", resp.StatusCode)
	}

	records, err := audit.Query(ctx, conn, audit.Filter{Action: "path.provision"})
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("path.provision rows: got %d want 1", len(records))
	}
	if records[0].TargetID != path.ID || records[0].Result != audit.ResultOK {
		t.Errorf("row: %+v", records[0])
	}
}
