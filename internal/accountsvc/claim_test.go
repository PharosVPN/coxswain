// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package accountsvc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/accountsvc"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/enroll"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// newClaimService brings up an AccountSync service with ClaimEnrollment enabled
// (a CA + provisioning policy) and seeds a user who has enrolled an encryption
// key (so a claim can provision + seal a profile). It returns the client, the
// db, the seeded user id, and the CA bundle.
func newClaimService(t *testing.T) (accountv1.AccountSyncClient, *sql.DB, string, pki.Bundle) {
	return newClaimServiceWithKey(t, true)
}

// newClaimServiceWithKey is newClaimService with control over whether the seeded
// user has enrolled an ACCOUNT encryption key. With enrollAccountKey=false the
// user has no account key at all — the passphrase-less first-device case, where
// sealing must rely entirely on the device's own per-device key.
func newClaimServiceWithKey(t *testing.T, enrollAccountKey bool) (accountv1.AccountSyncClient, *sql.DB, string, pki.Bundle) {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{
		Email: "claim@example.com", Role: account.RoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if enrollAccountKey {
		// Enrol an account encryption key so a LEGACY claim can seal to it.
		kp, err := e2e.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		wrapped, err := e2e.WrapPrivateKey(passphrase, kp.Private)
		if err != nil {
			t.Fatalf("WrapPrivateKey: %v", err)
		}
		if err := account.SetEncryptionKey(ctx, conn, user.ID, kp.Public, wrapped); err != nil {
			t.Fatalf("SetEncryptionKey: %v", err)
		}
	}

	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	signing, _, err := profile.EnsureSigningKey(ctx, conn)
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}

	svc := accountsvc.New(conn)
	svc.SetClaimConfig(accountsvc.ClaimConfig{
		DeviceCA:         bundle.Device,
		ProvisionOpts:    provision.Options{VPNSubnet: "10.66.0.0/16"},
		FleetCAPEM:       bundle.Fleet.CertPEM,
		RelayAddr:        "relay.example.net:443",
		RelayServerName:  "relay.example.net",
		CAFingerprint:    bundle.Root.Fingerprint(),
		SigningPublicKey: signing.Public,
	})

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	accountv1.RegisterAccountSyncServer(srv, svc)
	go srv.Serve(lis) //nolint:errcheck // stops on Stop
	t.Cleanup(srv.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { cc.Close() })
	return accountv1.NewAccountSyncClient(cc), conn, user.ID, bundle
}

// deviceEncKey generates a device X25519 encryption keypair and returns the
// public half (the 32-byte key the device presents in a claim) and the keypair
// (for opening the sealed bundle in the passphrase-less test). The private half
// never leaves a real device; the test holds it only to verify decryption.
func deviceEncKey(t *testing.T) ([]byte, e2e.KeyPair) {
	t.Helper()
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp.Public, kp
}

// deviceCSR generates a device keypair and a PEM CSR. The returned key never
// leaves; only csrPEM crosses to coxswain.
func deviceCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "my-phone"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// fingerprintOf computes the "sha256:"-prefixed fingerprint of a PEM cert, the
// shape coxswain stores + the relay forwards.
func fingerprintOf(certPEM []byte) string {
	sum := sha256.Sum256(certPEM)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestClaimEnrollmentSuccess(t *testing.T) {
	client, conn, userID, _ := newClaimService(t)
	ctx := context.Background()

	ticket, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}

	encPub, _ := deviceEncKey(t)
	resp, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token:            token,
		CsrPem:           deviceCSR(t),
		DeviceName:       "my-phone",
		Platform:         "ios",
		EncryptionPubkey: encPub,
	})
	if err != nil {
		t.Fatalf("ClaimEnrollment: %v", err)
	}
	if len(resp.GetDeviceCertPem()) == 0 || len(resp.GetFleetCaPem()) == 0 {
		t.Fatal("response missing device cert / fleet CA")
	}
	if resp.GetRelayAddr() != "relay.example.net:443" || resp.GetRelayServerName() != "relay.example.net" {
		t.Errorf("relay details: addr=%q name=%q", resp.GetRelayAddr(), resp.GetRelayServerName())
	}
	if resp.GetCaFingerprint() == "" || len(resp.GetSigningPublicKey()) == 0 {
		t.Error("response missing CA fingerprint / signing key")
	}

	// A device was created for the ticket's user, with the fingerprint of the
	// returned leaf.
	want := fingerprintOf(resp.GetDeviceCertPem())
	dev, err := account.GetDeviceByFingerprint(ctx, conn, want)
	if err != nil {
		t.Fatalf("device not created with the cert fingerprint: %v", err)
	}
	if dev.UserID != userID {
		t.Errorf("device user: got %q want %q", dev.UserID, userID)
	}
	if dev.Name != "my-phone" || dev.Platform != "ios" || dev.Status != account.StatusActive {
		t.Errorf("device fields: %+v", dev)
	}

	// The device was provisioned: a sealed profile exists for it.
	var profiles int
	if err := conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM profiles WHERE device_id = ?`, dev.ID).Scan(&profiles); err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	if profiles == 0 {
		t.Error("device was not provisioned (no profile rows)")
	}

	// The ticket is marked used + records which device claimed it.
	var usedAt sql.NullTime
	var usedBy sql.NullString
	if err := conn.QueryRowContext(ctx,
		`SELECT used_at, used_by_device_id FROM enrollment_tickets WHERE id = ?`, ticket.ID,
	).Scan(&usedAt, &usedBy); err != nil {
		t.Fatalf("read ticket: %v", err)
	}
	if !usedAt.Valid {
		t.Error("ticket used_at not stamped")
	}
	if usedBy.String != dev.ID {
		t.Errorf("ticket used_by_device_id: got %q want %q", usedBy.String, dev.ID)
	}
}

func TestClaimEnrollmentSingleUse(t *testing.T) {
	client, conn, userID, _ := newClaimService(t)
	ctx := context.Background()

	_, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	encPub, _ := deviceEncKey(t)
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), DeviceName: "first", EncryptionPubkey: encPub,
	}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// A second claim with the same token must fail.
	encPub2, _ := deviceEncKey(t)
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), DeviceName: "second", EncryptionPubkey: encPub2,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("second claim: got %v want Unauthenticated", err)
	}
	// Only the first device exists.
	devs, err := account.ListDevicesByUser(ctx, conn, userID)
	if err != nil {
		t.Fatalf("ListDevicesByUser: %v", err)
	}
	if len(devs) != 1 {
		t.Errorf("device count after a replayed claim: got %d want 1", len(devs))
	}
}

func TestClaimEnrollmentExpiredTicket(t *testing.T) {
	client, conn, userID, _ := newClaimService(t)
	ctx := context.Background()

	_, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	// Force the ticket past its expiry.
	if _, err := conn.ExecContext(ctx,
		`UPDATE enrollment_tickets SET expires_at = ?`, time.Now().UTC().Add(-time.Hour),
	); err != nil {
		t.Fatalf("expire ticket: %v", err)
	}
	encPub, _ := deviceEncKey(t)
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), EncryptionPubkey: encPub,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired: got %v want Unauthenticated", err)
	}
}

func TestClaimEnrollmentUnknownToken(t *testing.T) {
	client, _, _, _ := newClaimService(t)
	encPub, _ := deviceEncKey(t)
	_, err := client.ClaimEnrollment(context.Background(), &accountv1.ClaimEnrollmentRequest{
		Token: "no-such-token", CsrPem: deviceCSR(t), EncryptionPubkey: encPub,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unknown token: got %v want Unauthenticated", err)
	}
}

func TestClaimEnrollmentBadCSR(t *testing.T) {
	client, conn, userID, _ := newClaimService(t)
	ctx := context.Background()

	_, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	encPub, _ := deviceEncKey(t)
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: []byte("not a csr"), EncryptionPubkey: encPub,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad CSR: got %v want InvalidArgument", err)
	}
	// A bad CSR fails BEFORE the ticket is redeemed, so the token still works.
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), EncryptionPubkey: encPub,
	}); err != nil {
		t.Fatalf("claim after a bad-CSR attempt should still work: %v", err)
	}
}

func TestClaimEnrollmentMissingArgs(t *testing.T) {
	client, _, _, _ := newClaimService(t)
	ctx := context.Background()
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{CsrPem: deviceCSR(t)}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no token: got %v want InvalidArgument", err)
	}
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{Token: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no CSR: got %v want InvalidArgument", err)
	}
}

// TestClaimEnrollmentBadEncryptionKey covers the join flow's requirement that the
// device present a valid 32-byte X25519 encryption public key: a missing or
// short key is InvalidArgument (the passphrase-less seal has no recipient
// otherwise). A valid token is supplied so the rejection is provably the key,
// not the token — and the token survives, because the key is checked before the
// ticket is redeemed.
func TestClaimEnrollmentBadEncryptionKey(t *testing.T) {
	client, conn, userID, _ := newClaimService(t)
	ctx := context.Background()

	_, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	// Missing key.
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t),
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing encryption key: got %v want InvalidArgument", err)
	}
	// Short (not 32 bytes).
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), EncryptionPubkey: []byte("too-short"),
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("short encryption key: got %v want InvalidArgument", err)
	}
	// The token was never redeemed by either rejected claim — a valid one works.
	encPub, _ := deviceEncKey(t)
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), EncryptionPubkey: encPub,
	}); err != nil {
		t.Fatalf("claim with a valid key after rejections should work: %v", err)
	}
}

// TestClaimEnrollmentDisabled covers a service built WITHOUT a claim config —
// the RPC is Unimplemented, never a panic.
func TestClaimEnrollmentDisabled(t *testing.T) {
	client, conn, userID := newService(t) // the plain service, no claim config
	_, token, err := enroll.IssueTicket(context.Background(), conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}
	_, err = client.ClaimEnrollment(context.Background(), &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t),
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("claim with no config: got %v want Unimplemented", err)
	}
}

// TestClaimEnrollmentPassphraseless is the headline case: a user with NO enrolled
// account encryption key joins their FIRST device via the join-link flow. The
// device generates its own X25519 key and presents the public half; coxswain
// provisions + seals the bundle to THAT key. Before this change the claim failed
// with ErrNoEncryptionKey (no recipient to seal to); now it must succeed, and the
// sealed bundle must open with the DEVICE's private key and ONLY that key — never
// any account passphrase, which the user never set.
func TestClaimEnrollmentPassphraseless(t *testing.T) {
	// enrollAccountKey=false: the user has no account key whatsoever.
	client, conn, userID, _ := newClaimServiceWithKey(t, false)
	ctx := context.Background()

	// Sanity: the user truly has no account encryption key.
	if pub, _, err := account.GetEncryptionKey(ctx, conn, userID); err != nil || len(pub) != 0 {
		t.Fatalf("seed user should have no account key: pub=%d err=%v", len(pub), err)
	}

	_, token, err := enroll.IssueTicket(ctx, conn, userID)
	if err != nil {
		t.Fatalf("IssueTicket: %v", err)
	}

	encPub, devKP := deviceEncKey(t)
	resp, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), DeviceName: "first-phone", Platform: "android",
		EncryptionPubkey: encPub,
	})
	if err != nil {
		t.Fatalf("passphrase-less claim should succeed, got: %v", err)
	}

	// The device row carries its own encryption key.
	dev, err := account.GetDeviceByFingerprint(ctx, conn, fingerprintOf(resp.GetDeviceCertPem()))
	if err != nil {
		t.Fatalf("device not created: %v", err)
	}
	if !dev.HasEncryptionKey() || string(dev.EncryptionPubkey) != string(encPub) {
		t.Fatalf("device encryption key not stored: %x", dev.EncryptionPubkey)
	}

	// The provisioned bundle opens with the DEVICE's private key.
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
	plaintext, err := e2e.Open(bundle, devKP.Private, signing.Public)
	if err != nil {
		t.Fatalf("bundle must open with the device's own key (no passphrase): %v", err)
	}
	var prof profile.Profile
	if err := json.Unmarshal(plaintext, &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if prof.User != userID {
		t.Errorf("decrypted profile user: got %q want %q", prof.User, userID)
	}

	// A DIFFERENT key (someone else's, e.g. a hypothetical account key) must NOT
	// open the bundle — the seal is to the device, not the account.
	other, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := e2e.Open(bundle, other.Private, signing.Public); err == nil {
		t.Error("bundle opened with a foreign key — it is not sealed to the device")
	}
}

// TestClaimEnrollmentLegacySealsToAccountKey guards the back-compat path: when a
// device's bundle is sealed to the account key path (resolveRecipient's
// fallback), it opens with the ACCOUNT key. The join flow always supplies a
// per-device key, so this asserts the fallback directly: a device with no
// per-device key (e.g. a legacy account-sync device) seals to the user's account
// key, unchanged.
func TestClaimEnrollmentLegacySealsToAccountKey(t *testing.T) {
	conn := mustMigratedDB(t)
	ctx := context.Background()

	user, err := account.CreateUser(ctx, conn, account.User{Email: "legacy@example.com", Role: account.RoleUser})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	acctKP, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	wrapped, err := e2e.WrapPrivateKey(passphrase, acctKP.Private)
	if err != nil {
		t.Fatalf("WrapPrivateKey: %v", err)
	}
	if err := account.SetEncryptionKey(ctx, conn, user.ID, acctKP.Public, wrapped); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}

	// A device with NO per-device encryption key (the legacy account-sync shape).
	dev, err := account.CreateDevice(ctx, conn, account.Device{UserID: user.ID, Name: "legacy"})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if dev.HasEncryptionKey() {
		t.Fatal("legacy device should carry no per-device key")
	}

	if _, err := profile.Issue(ctx, conn, user.ID, dev.ID, profile.Profile{FleetID: "f"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ciphertext, _, err := profile.LatestCiphertext(ctx, conn, user.ID, dev.ID)
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
	// Opens with the ACCOUNT key (the fallback recipient), not any device key.
	if _, err := e2e.Open(bundle, acctKP.Private, signing.Public); err != nil {
		t.Fatalf("legacy device bundle must open with the account key: %v", err)
	}
}

// mustMigratedDB opens a fresh migrated SQLite db for the package's lower-level
// tests (no gRPC plumbing).
func mustMigratedDB(t *testing.T) *sql.DB {
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
