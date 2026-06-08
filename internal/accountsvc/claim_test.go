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
	// Enrol an encryption key so ProvisionDevice can seal a profile bundle.
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

	resp, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token:      token,
		CsrPem:     deviceCSR(t),
		DeviceName: "my-phone",
		Platform:   "ios",
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
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), DeviceName: "first",
	}); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// A second claim with the same token must fail.
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t), DeviceName: "second",
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
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired: got %v want Unauthenticated", err)
	}
}

func TestClaimEnrollmentUnknownToken(t *testing.T) {
	client, _, _, _ := newClaimService(t)
	_, err := client.ClaimEnrollment(context.Background(), &accountv1.ClaimEnrollmentRequest{
		Token: "no-such-token", CsrPem: deviceCSR(t),
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
	_, err = client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: []byte("not a csr"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad CSR: got %v want InvalidArgument", err)
	}
	// A bad CSR fails BEFORE the ticket is redeemed, so the token still works.
	if _, err := client.ClaimEnrollment(ctx, &accountv1.ClaimEnrollmentRequest{
		Token: token, CsrPem: deviceCSR(t),
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
