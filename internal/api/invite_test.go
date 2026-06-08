// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/authn"
)

func TestInviteUser(t *testing.T) {
	ts, client, _, srv := setupServer(t)
	srv.SetRelayEndpoint("relay.example.net:443")
	login(t, ts, client)

	// Seed a user.
	uResp, err := client.Post(ts.URL+"/api/users", "application/json",
		strings.NewReader(`{"name":"U","email":"u@example.com"}`))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var user userView
	json.NewDecoder(uResp.Body).Decode(&user) //nolint:errcheck
	uResp.Body.Close()

	// Issue an invite.
	resp, err := client.Post(ts.URL+"/api/users/"+user.ID+"/invite", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("invite: status %d want 201", resp.StatusCode)
	}
	var out struct {
		URL       string `json:"url"`
		QRPNG     string `json:"qr_png_base64"`
		ExpiresAt string `json:"expires_at"`
		TicketID  string `json:"ticket_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(out.URL, "pharosvpn://enroll?") {
		t.Errorf("url: got %q want a pharosvpn://enroll link", out.URL)
	}
	if !strings.Contains(out.URL, "relay=relay.example.net%3A443") {
		t.Errorf("url missing the configured relay: %q", out.URL)
	}
	if out.ExpiresAt == "" || out.TicketID == "" {
		t.Errorf("invite missing expiry/ticket: %+v", out)
	}
	// The QR is a real PNG.
	png, err := base64.StdEncoding.DecodeString(out.QRPNG)
	if err != nil {
		t.Fatalf("qr not base64: %v", err)
	}
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Errorf("qr_png_base64 is not a PNG (got %d bytes)", len(png))
	}
}

func TestInviteUnknownUser(t *testing.T) {
	ts, client, _, srv := setupServer(t)
	srv.SetRelayEndpoint("relay.example.net:443")
	login(t, ts, client)

	resp, err := client.Post(ts.URL+"/api/users/nope/invite", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown user: status %d want 404", resp.StatusCode)
	}
}

func TestInviteNoRelayConfigured(t *testing.T) {
	ts, client, _, _ := setupServer(t) // relay endpoint left unset
	login(t, ts, client)

	uResp, err := client.Post(ts.URL+"/api/users", "application/json",
		strings.NewReader(`{"name":"U","email":"u2@example.com"}`))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	var user userView
	json.NewDecoder(uResp.Body).Decode(&user) //nolint:errcheck
	uResp.Body.Close()

	resp, err := client.Post(ts.URL+"/api/users/"+user.ID+"/invite", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("no relay: status %d want 409", resp.StatusCode)
	}
}

// TestInviteRequiresAdmin proves the route is admin-scoped: a readonly token may
// not issue invites (403 before any user lookup).
func TestInviteRequiresAdmin(t *testing.T) {
	ts, _, conn, srv := setupServer(t)
	srv.SetRelayEndpoint("relay.example.net:443")

	secret, _, err := authn.Create(context.Background(), conn, "ci-ro", authn.ScopeReadonly, 0, "test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	resp := bearerReq(t, ts, http.MethodPost, "/api/users/whatever/invite", secret, `{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("readonly invite: status %d want 403", resp.StatusCode)
	}
}
