// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package fleet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

func TestIssueAndRedeemToken(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	tok, secret, err := fleet.IssueToken(ctx, conn, fleet.KindBuoy, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if secret == "" || tok.ID == "" {
		t.Fatal("IssueToken: empty secret or id")
	}
	if tok.Used() {
		t.Error("freshly issued token reports Used()")
	}
	if !tok.ExpiresAt.After(time.Now()) {
		t.Error("token already expired on issue")
	}

	redeemed, err := fleet.RedeemToken(ctx, conn, secret)
	if err != nil {
		t.Fatalf("RedeemToken: %v", err)
	}
	if !redeemed.Used() {
		t.Error("redeemed token does not report Used()")
	}
}

func TestRedeemTokenTwice(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	_, secret, err := fleet.IssueToken(ctx, conn, fleet.KindBuoy, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := fleet.RedeemToken(ctx, conn, secret); err != nil {
		t.Fatalf("first RedeemToken: %v", err)
	}
	if _, err := fleet.RedeemToken(ctx, conn, secret); !errors.Is(err, fleet.ErrTokenUsed) {
		t.Fatalf("second RedeemToken: got %v want ErrTokenUsed", err)
	}
}

func TestRedeemTokenInvalid(t *testing.T) {
	conn := newDB(t)
	if _, err := fleet.RedeemToken(context.Background(), conn, "not-a-real-token"); !errors.Is(err, fleet.ErrTokenInvalid) {
		t.Fatalf("got %v want ErrTokenInvalid", err)
	}
}

func TestRedeemTokenExpired(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()

	tok, secret, err := fleet.IssueToken(ctx, conn, fleet.KindBeacon, "")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	// Backdate expiry past now.
	if _, err := conn.ExecContext(ctx,
		`UPDATE bootstrap_tokens SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Hour).UTC(), tok.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := fleet.RedeemToken(ctx, conn, secret); !errors.Is(err, fleet.ErrTokenExpired) {
		t.Fatalf("got %v want ErrTokenExpired", err)
	}
}

func TestIssueTokenUnknownKind(t *testing.T) {
	conn := newDB(t)
	if _, _, err := fleet.IssueToken(context.Background(), conn, "router", ""); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}
