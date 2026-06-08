// SPDX-License-Identifier: Apache-2.0
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

	rev, err := profile.Issue(ctx, conn, userID, "", profile.Profile{
		FleetID: "fleet-1",
		Profiles: []profile.ClientProfile{
			{ID: "pspec_a", Name: "Direct", Protocol: profile.ProtocolAmneziaWG, Nodes: []profile.Node{
				{ID: "nod_a", Name: "ams-1", Region: "eu", Endpoints: []string{"203.0.113.7:443"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if rev != 1 {
		t.Errorf("first revision: got %d want 1", rev)
	}

	ciphertext, gotRev, err := profile.LatestCiphertext(ctx, conn, userID, "")
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
	if got.User != userID || got.Revision != 1 || len(got.Profiles) != 1 || len(got.Profiles[0].Nodes) != 1 {
		t.Errorf("decrypted profile mismatch: %+v", got)
	}
}

func TestIssueRevisionIncrements(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, _ := enrolledUser(t, conn, "pw")

	for want := int64(1); want <= 3; want++ {
		rev, err := profile.Issue(ctx, conn, userID, "", profile.Profile{FleetID: "f"})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if rev != want {
			t.Errorf("revision: got %d want %d", rev, want)
		}
	}
}

// TestIssuePerDevice guards device-aware profiles: a user's devices each get
// their own profile and their own revision sequence, and LatestCiphertext
// returns the right device's latest — so account sync hands a device its own
// profile, not another device's.
func TestIssuePerDevice(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, _ := enrolledUser(t, conn, "pw")
	devA, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "a"})
	if err != nil {
		t.Fatalf("CreateDevice a: %v", err)
	}
	devB, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "b"})
	if err != nil {
		t.Fatalf("CreateDevice b: %v", err)
	}

	// Device A advances to revision 2; device B's sequence is independent.
	mustIssue := func(devID, fleet string, want int64) {
		rev, err := profile.Issue(ctx, conn, userID, devID, profile.Profile{FleetID: fleet})
		if err != nil {
			t.Fatalf("Issue %s: %v", fleet, err)
		}
		if rev != want {
			t.Errorf("Issue %s revision: got %d want %d", fleet, rev, want)
		}
	}
	mustIssue(devA.ID, "a1", 1)
	mustIssue(devA.ID, "a2", 2)
	mustIssue(devB.ID, "b1", 1) // independent of A

	_, revA, err := profile.LatestCiphertext(ctx, conn, userID, devA.ID)
	if err != nil || revA != 2 {
		t.Fatalf("device A latest: rev %d err %v (want rev 2)", revA, err)
	}
	_, revB, err := profile.LatestCiphertext(ctx, conn, userID, devB.ID)
	if err != nil || revB != 1 {
		t.Fatalf("device B latest: rev %d err %v (want rev 1)", revB, err)
	}
	// A user with per-device profiles has no legacy per-user profile.
	if _, _, err := profile.LatestCiphertext(ctx, conn, userID, ""); !errors.Is(err, profile.ErrNoProfile) {
		t.Errorf("legacy per-user lookup: got %v want ErrNoProfile", err)
	}
}

// TestIssueSealsToDeviceKey guards per-device sealing: a device created with its
// own X25519 encryption key gets its profile sealed to THAT key — it opens with
// the device's private key and does NOT open with the user's account key. This
// is the passphrase-less join-link recipient resolution.
func TestIssueSealsToDeviceKey(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, userKP := enrolledUser(t, conn, "pw")

	// A device with its OWN encryption key (the join-link shape).
	devKP, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dev, err := account.CreateDevice(ctx, conn, account.Device{
		UserID: userID, Name: "joined", EncryptionPubkey: devKP.Public,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	if _, err := profile.Issue(ctx, conn, userID, dev.ID, profile.Profile{FleetID: "f"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ciphertext, _, err := profile.LatestCiphertext(ctx, conn, userID, dev.ID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(ciphertext, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	// Opens with the device key.
	if _, err := e2e.Open(bundle, devKP.Private, signing.Public); err != nil {
		t.Fatalf("bundle must open with the device key: %v", err)
	}
	// Does NOT open with the user's account key — it was sealed to the device.
	if _, err := e2e.Open(bundle, userKP.Private, signing.Public); err == nil {
		t.Error("bundle opened with the user's account key — it should be sealed to the device")
	}
}

// TestIssueDeviceWithoutKeyFallsBackToAccountKey guards the legacy path: a device
// with NO per-device key seals to the user's account key (unchanged behaviour).
func TestIssueDeviceWithoutKeyFallsBackToAccountKey(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	userID, userKP := enrolledUser(t, conn, "pw")

	dev, err := account.CreateDevice(ctx, conn, account.Device{UserID: userID, Name: "legacy"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if _, err := profile.Issue(ctx, conn, userID, dev.ID, profile.Profile{FleetID: "f"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ciphertext, _, err := profile.LatestCiphertext(ctx, conn, userID, dev.ID)
	if err != nil {
		t.Fatalf("LatestCiphertext: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(ciphertext, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if _, err := e2e.Open(bundle, userKP.Private, signing.Public); err != nil {
		t.Fatalf("legacy device bundle must open with the account key: %v", err)
	}
}

func TestIssueWithoutEncryptionKey(t *testing.T) {
	conn := newDB(t)
	ctx := context.Background()
	u, err := account.CreateUser(ctx, conn, account.User{Email: "nokey@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := profile.Issue(ctx, conn, u.ID, "", profile.Profile{}); !errors.Is(err, profile.ErrNoEncryptionKey) {
		t.Fatalf("got %v want ErrNoEncryptionKey", err)
	}
}

func TestLatestCiphertextNoProfile(t *testing.T) {
	conn := newDB(t)
	if _, _, err := profile.LatestCiphertext(context.Background(), conn, "usr_missing", ""); !errors.Is(err, profile.ErrNoProfile) {
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
