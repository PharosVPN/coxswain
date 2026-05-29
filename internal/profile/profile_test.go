// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package profile_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/profile"
)

func newDB(t *testing.T) *sql.DB {
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

// enrolledUser creates a user with an X25519 encryption key sealed under
// passphrase, and returns the user ID and the key material for verification.
func enrolledUser(t *testing.T, conn *sql.DB, passphrase string) (string, e2e.KeyPair) {
	t.Helper()
	ctx := context.Background()
	u, err := account.CreateUser(ctx, conn, account.User{Email: "u@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	wrapped, err := e2e.WrapPrivateKey(passphrase, kp.Private)
	if err != nil {
		t.Fatalf("WrapPrivateKey: %v", err)
	}
	if err := account.SetEncryptionKey(ctx, conn, u.ID, kp.Public, wrapped); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	return u.ID, kp
}

func TestIssueAndOpenRoundTrip(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	const passphrase = "a-strong-account-passphrase"
	userID, _ := enrolledUser(t, conn, passphrase)

	rev, err := profile.Issue(ctx, conn, userID, profile.Profile{
		FleetID: "fleet-1",
		Nodes: []profile.Node{
			{ID: "nod_a", Name: "ams-1", Region: "eu", Endpoints: []string{"203.0.113.7:443"}},
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if rev != 1 {
		t.Errorf("first revision: got %d want 1", rev)
	}

	ciphertext, gotRev, err := profile.LatestCiphertext(ctx, conn, userID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	if gotRev != 1 {
		t.Errorf("revision: got %d want 1", gotRev)
	}

	// A user device opens the bundle: unwrap the private key with the
	// passphrase, verify against coxswain's signing key, decrypt.
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(ciphertext, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	priv, err := e2e.UnwrapPrivateKey(passphrase, mustWrapped(t, conn, userID))
	if err != nil {
		t.Fatalf("UnwrapPrivateKey: %v", err)
	}
	plaintext, err := e2e.Open(bundle, priv, signing.Public)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var got profile.Profile
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if got.User != userID || got.Revision != 1 || len(got.Nodes) != 1 {
		t.Errorf("decrypted profile mismatch: %+v", got)
	}
}

func TestIssueRevisionIncrements(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, _ := enrolledUser(t, conn, "pw")

	for want := int64(1); want <= 3; want++ {
		rev, err := profile.Issue(ctx, conn, userID, profile.Profile{FleetID: "f"})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if rev != want {
			t.Errorf("revision: got %d want %d", rev, want)
		}
	}
}

func TestIssueWithoutEncryptionKey(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	u, err := account.CreateUser(ctx, conn, account.User{Email: "nokey@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := profile.Issue(ctx, conn, u.ID, profile.Profile{}); !errors.Is(err, profile.ErrNoEncryptionKey) {
		t.Fatalf("got %v want ErrNoEncryptionKey", err)
	}
}

func TestLatestCiphertextNoProfile(t *testing.T) {
	conn := newDB(t)
	if _, _, err := profile.LatestCiphertext(context.Background(), conn, "usr_missing"); !errors.Is(err, profile.ErrNoProfile) {
		t.Fatalf("got %v want ErrNoProfile", err)
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		psk := profile.GeneratePresharedKey()
		if len(psk) != 44 { // base64 of 32 bytes
			t.Fatalf("PSK length: got %d want 44 (%q)", len(psk), psk)
		}
		if seen[psk] {
			t.Fatal("duplicate preshared key")
		}
		seen[psk] = true
	}
}

func TestEnsureSigningKeyIdempotent(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	first, created, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil || !created {
		t.Fatalf("first EnsureSigningKey: created=%v err=%v", created, err)
	}
	second, created, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil || created {
		t.Fatalf("second EnsureSigningKey: created=%v err=%v", created, err)
	}
	if string(first.Public) != string(second.Public) {
		t.Error("signing key changed across calls")
	}
}

func mustWrapped(t *testing.T, conn *sql.DB, userID string) []byte {
	t.Helper()
	_, wrapped, err := account.GetEncryptionKey(context.Background(), conn, userID)
	if err != nil {
		t.Fatalf("GetEncryptionKey: %v", err)
	}
	return wrapped
}
