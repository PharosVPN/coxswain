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
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
	qrcode "github.com/skip2/go-qrcode"
)

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

// IssueTicket mints a one-time enrollment ticket for a user and returns the
// stored record plus the plaintext token (shown once, never persisted).
func IssueTicket(ctx context.Context, db *sql.DB, userID string) (Ticket, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Ticket{}, "", fmt.Errorf("enroll: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now().UTC()
	t := Ticket{
		ID:        idgen.New("tkt"),
		UserID:    userID,
		ExpiresAt: now.Add(TicketTTL),
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
