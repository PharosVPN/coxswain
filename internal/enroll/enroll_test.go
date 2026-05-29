// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package enroll_test

import (
	"bytes"
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/enroll"
)

func TestIssueTicket(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Email: "u@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	ticket, token, err := enroll.IssueTicket(ctx, conn, user.ID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	if ticket.ID == "" || token == "" || ticket.UserID != user.ID {
		t.Fatalf("ticket: %+v token=%q", ticket, token)
	}
	if !ticket.ExpiresAt.After(ticket.CreatedAt) {
		t.Error("ticket already expired on issue")
	}

	// The plaintext token must not be stored.
	var stored string
	if err := conn.QueryRowContext(ctx,
		`SELECT token_hash FROM enrollment_tickets WHERE id = ?`, ticket.ID).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored == token || stored == "" {
		t.Error("token stored in plaintext or missing")
	}
}

func TestTicketURL(t *testing.T) {
	link := enroll.TicketURL("relay.example:443", "tok+en/value", "abcdef123456")
	if !strings.HasPrefix(link, "pharosvpn://enroll?") {
		t.Fatalf("bad scheme: %q", link)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("relay") != "relay.example:443" || q.Get("ca") != "abcdef123456" {
		t.Errorf("query mismatch: %v", q)
	}
	if q.Get("token") != "tok+en/value" {
		t.Errorf("token not round-tripped: %q", q.Get("token"))
	}
}

func TestQRCode(t *testing.T) {
	png, err := enroll.QRCode("pharosvpn://enroll?token=x")
	if err != nil {
		t.Fatalf("QRCode: %v", err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Error("output is not a PNG")
	}
}
