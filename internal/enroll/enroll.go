// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package enroll issues device-enrollment tickets and renders them as QR
// codes (DESIGN §5, §9). A ticket is a one-time claim token plus the relay
// endpoint and CA fingerprint a scanning device needs.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
	qrcode "github.com/skip2/go-qrcode"
)

// ErrTicketInvalid is returned by RedeemTicket when the presented token names no
// ticket, the ticket has expired, or it was already claimed. The cases are
// deliberately collapsed into one opaque error so a caller (and thus a remote
// attacker) cannot distinguish "wrong token" from "expired" from "already used".
var ErrTicketInvalid = errors.New("enroll: ticket invalid, expired, or already used")

// TicketTTL is how long an enrollment ticket stays redeemable (DESIGN §5 —
// short TTL, one-use).
const TicketTTL = 24 * time.Hour

// Ticket is a stored enrollment ticket. coxswain keeps only the token's hash.
type Ticket struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IssueTicket mints a one-time enrollment ticket for a user with the default
// TTL and returns the stored record plus the plaintext token (shown once, never
// persisted).
func IssueTicket(ctx context.Context, db *sql.DB, userID string) (Ticket, string, error) {
	return IssueTicketTTL(ctx, db, userID, TicketTTL)
}

// IssueTicketTTL is IssueTicket with a caller-chosen lifetime. A non-positive ttl
// falls back to the default TicketTTL, so the ticket is always redeemable for a
// bounded, non-zero window.
func IssueTicketTTL(ctx context.Context, db *sql.DB, userID string, ttl time.Duration) (Ticket, string, error) {
	if ttl <= 0 {
		ttl = TicketTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Ticket{}, "", fmt.Errorf("enroll: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	t := Ticket{
		ID:        idgen.New("tkt"),
		UserID:    userID,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO enrollment_tickets (id, user_id, token_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.ID, userID, hashToken(token), t.ExpiresAt, t.CreatedAt,
	); err != nil {
		return Ticket{}, "", fmt.Errorf("enroll: store ticket: %w", err)
	}
	return t, token, nil
}

// RedeemTicket atomically claims a one-time enrollment ticket: it looks the
// ticket up by the token's hash, rejects it if missing / expired / already used,
// and stamps it spent (used_at + used_by_device_id) in a single conditional
// UPDATE. The UPDATE's WHERE clause (used_at IS NULL AND not expired) is the
// one-time guard — a second concurrent claim updates zero rows and gets
// ErrTicketInvalid, so the token can be redeemed at most once even under a race.
// It returns the claimed ticket (so the caller knows the user it was issued to).
//
// deviceID is the device this claim created; it is recorded for the audit trail.
// All failure modes collapse to ErrTicketInvalid so the path cannot be probed.
func RedeemTicket(ctx context.Context, db *sql.DB, token, deviceID string) (Ticket, error) {
	if token == "" {
		return Ticket{}, ErrTicketInvalid
	}
	want := hashToken(token)

	var (
		t       Ticket
		gotHash string
		usedAt  sql.NullTime
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, expires_at, used_at, created_at
		   FROM enrollment_tickets WHERE token_hash = ?`, want,
	).Scan(&t.ID, &t.UserID, &gotHash, &t.ExpiresAt, &usedAt, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Ticket{}, ErrTicketInvalid
	}
	if err != nil {
		return Ticket{}, fmt.Errorf("enroll: load ticket: %w", err)
	}
	// Defence in depth: the lookup already matched on the hash, but compare in
	// constant time so the path is uniform regardless of how the row was found
	// (mirrors the API-token authenticate path).
	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(want)) != 1 {
		return Ticket{}, ErrTicketInvalid
	}
	now := time.Now().UTC()
	if usedAt.Valid || !t.ExpiresAt.After(now) {
		return Ticket{}, ErrTicketInvalid
	}

	// Conditional one-time claim: only a still-unused, still-valid ticket is
	// stamped. A racing second claim sees used_at already set and updates 0 rows.
	res, err := db.ExecContext(ctx,
		`UPDATE enrollment_tickets
		    SET used_at = ?, used_by_device_id = ?
		  WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now, deviceID, want, now,
	)
	if err != nil {
		return Ticket{}, fmt.Errorf("enroll: claim ticket: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Ticket{}, fmt.Errorf("enroll: claim ticket: %w", err)
	}
	if n == 0 {
		return Ticket{}, ErrTicketInvalid
	}
	return t, nil
}

// TicketURL builds the deep link a device imports. caravel registers the
// pharosvpn:// scheme; the QR encodes this URL.
func TicketURL(relayEndpoint, token, caFingerprint string) string {
	q := url.Values{}
	q.Set("relay", relayEndpoint)
	q.Set("token", token)
	q.Set("ca", caFingerprint)
	return "pharosvpn://enroll?" + q.Encode()
}

// QRCode renders content as a PNG QR code.
func QRCode(content string) ([]byte, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 512)
	if err != nil {
		return nil, fmt.Errorf("enroll: render QR: %w", err)
	}
	return png, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
