// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

const testAdminPassword = "test-admin-password"

// newTestDB opens a migrated, throwaway database for a test.
func newTestDB(t *testing.T) *sql.DB {
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

// setup builds a migrated database, the synced fixed admin, and a running
// test HTTP server with a cookie-jar client.
func setup(t *testing.T) (*httptest.Server, *http.Client, *sql.DB) {
	t.Helper()
	conn := newTestDB(t)
	if err := auth.SyncConfigAdmin(context.Background(), conn, testAdminPassword); err != nil {
		t.Fatalf("SyncConfigAdmin: %v", err)
	}

	srv := NewServer("", conn, live.NewHub(), provision.Options{
		VPNSubnet: "10.86.0.0/16", PortMin: 2000, PortMax: 60000,
	}, nil, nil, nil, "")
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}, conn
}

// login authenticates the client as the fixed admin.
func login(t *testing.T, ts *httptest.Server, client *http.Client) {
	t.Helper()
	resp, err := client.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	ts, client, _ := setup(t)
	resp, err := client.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"wrong"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", resp.StatusCode)
	}
}

func TestLoginThenMe(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	resp, err := client.Get(ts.URL + "/api/auth/me")
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: status %d", resp.StatusCode)
	}
	var me userView
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if me.Email != account.FixedAdminEmail || me.Role != account.RoleAdmin {
		t.Errorf("me: %+v", me)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	ts, client, _ := setup(t)
	resp, err := client.Get(ts.URL + "/api/nodes")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", resp.StatusCode)
	}
}

func TestNodeUpdateOptimisticConcurrency(t *testing.T) {
	ts, client, conn := setup(t)
	login(t, ts, client)

	node, err := fleet.CreateNode(context.Background(), conn,
		fleet.Node{Name: "ams-1", Region: "eu"})
	if err != nil {
		t.Fatalf("seed node: %v", err)
	}

	// A fresh-version rename succeeds.
	if code := patchNode(t, client, ts, node.ID, node.Version, "ams-renamed"); code != http.StatusOK {
		t.Fatalf("fresh PATCH: status %d want 200", code)
	}
	// The same (now stale) version is rejected with 409.
	if code := patchNode(t, client, ts, node.ID, node.Version, "ams-again"); code != http.StatusConflict {
		t.Fatalf("stale PATCH: status %d want 409", code)
	}
}

func TestAdminsLifecycle(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	// Create a second admin.
	resp, err := client.Post(ts.URL+"/api/admins", "application/json",
		strings.NewReader(`{"email":"ops@example.com","password":"longenough"}`))
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	var created userView
	json.NewDecoder(resp.Body).Decode(&created) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create admin: status %d", resp.StatusCode)
	}

	// List shows both the fixed admin and the new one.
	listResp, err := client.Get(ts.URL + "/api/admins")
	if err != nil {
		t.Fatalf("list admins: %v", err)
	}
	var admins []userView
	json.NewDecoder(listResp.Body).Decode(&admins) //nolint:errcheck
	listResp.Body.Close()
	if len(admins) != 2 {
		t.Fatalf("admins: got %d want 2", len(admins))
	}

	// The created admin can be deleted.
	if code := deleteReq(t, client, ts.URL+"/api/admins/"+created.ID); code != http.StatusNoContent {
		t.Errorf("delete created admin: status %d want 204", code)
	}
	// The fixed admin cannot.
	if code := deleteReq(t, client, ts.URL+"/api/admins/"+account.FixedAdminID); code != http.StatusForbidden {
		t.Errorf("delete fixed admin: status %d want 403", code)
	}
}

func TestUsersLifecycle(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	resp, err := client.Post(ts.URL+"/api/users", "application/json",
		strings.NewReader(`{"name":"Test User","email":"user@example.com","password":"longenough"}`))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var created userView
	json.NewDecoder(resp.Body).Decode(&created) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user: status %d", resp.StatusCode)
	}
	if created.Role != account.RoleUser {
		t.Errorf("role: got %q want user", created.Role)
	}

	listResp, err := client.Get(ts.URL + "/api/users")
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	var users []userView
	json.NewDecoder(listResp.Body).Decode(&users) //nolint:errcheck
	listResp.Body.Close()
	if len(users) != 1 {
		t.Fatalf("users: got %d want 1", len(users))
	}

	if code := deleteReq(t, client, ts.URL+"/api/users/"+created.ID); code != http.StatusNoContent {
		t.Errorf("delete user: status %d want 204", code)
	}
}

func TestNetworkPolicyPreview(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	// A valid policy returns the rule set.
	resp, err := client.Post(ts.URL+"/api/network-policy/preview", "application/json",
		strings.NewReader(`{"forwarding":true,"masquerade":true,"isolation":false}`))
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	var rules struct {
		PostUp []string `json:"post_up"`
	}
	json.NewDecoder(resp.Body).Decode(&rules) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview: status %d", resp.StatusCode)
	}
	if len(rules.PostUp) == 0 {
		t.Error("preview returned no PostUp rules")
	}

	// An invalid policy is rejected.
	bad, err := client.Post(ts.URL+"/api/network-policy/preview", "application/json",
		strings.NewReader(`{"forwarding":false,"masquerade":true,"isolation":false}`))
	if err != nil {
		t.Fatalf("preview (invalid): %v", err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid policy: status %d want 400", bad.StatusCode)
	}
}

func TestDevicesAndProvision(t *testing.T) {
	ts, client, _ := setup(t)
	login(t, ts, client)

	uResp, err := client.Post(ts.URL+"/api/users", "application/json",
		strings.NewReader(`{"name":"U","email":"u@example.com","password":"longenough"}`))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var user userView
	json.NewDecoder(uResp.Body).Decode(&user) //nolint:errcheck
	uResp.Body.Close()

	dResp, err := client.Post(ts.URL+"/api/users/"+user.ID+"/devices", "application/json",
		strings.NewReader(`{"name":"phone","platform":"android"}`))
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	var device deviceView
	json.NewDecoder(dResp.Body).Decode(&device) //nolint:errcheck
	dResp.Body.Close()
	if dResp.StatusCode != http.StatusCreated {
		t.Fatalf("create device: status %d", dResp.StatusCode)
	}

	listResp, err := client.Get(ts.URL + "/api/users/" + user.ID + "/devices")
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	var devices []deviceView
	json.NewDecoder(listResp.Body).Decode(&devices) //nolint:errcheck
	listResp.Body.Close()
	if len(devices) != 1 {
		t.Fatalf("devices: got %d want 1", len(devices))
	}

	// Provisioning a device whose user has no encryption key is a 409.
	pResp, err := client.Post(ts.URL+"/api/devices/"+device.ID+"/provision",
		"application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	pResp.Body.Close()
	if pResp.StatusCode != http.StatusConflict {
		t.Errorf("provision without keys: status %d want 409", pResp.StatusCode)
	}

	if code := deleteReq(t, client, ts.URL+"/api/devices/"+device.ID); code != http.StatusNoContent {
		t.Errorf("delete device: status %d want 204", code)
	}
}

func patchNode(t *testing.T, client *http.Client, ts *httptest.Server, id string, version int, name string) int {
	t.Helper()
	body := `{"version":` + strconv.Itoa(version) + `,"name":"` + name + `"}`
	req, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/nodes/"+id, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func deleteReq(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
