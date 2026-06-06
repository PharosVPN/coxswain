// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package accountsvc_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/accountsvc"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/e2e"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/profile"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const passphrase = "the-account-passphrase"

// newService brings up the AccountSync service over an in-memory connection
// (the same in-process model the embedded relay will use) and seeds a user.
func newService(t *testing.T) (accountv1.AccountSyncClient, *sql.DB, string) {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	hash, err := auth.HashPassword(passphrase)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user, err := account.CreateUser(context.Background(), conn, account.User{
		Email: "user@example.com", Role: account.RoleUser, PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	accountv1.RegisterAccountSyncServer(srv, accountsvc.New(conn))
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
	return accountv1.NewAccountSyncClient(cc), conn, user.ID
}

// withSession returns a context carrying the session token.
func withSession(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "pharos-session", token)
}

func TestAuthenticateAndProfileRoundTrip(t *testing.T) {
	client, conn, userID := newService(t)
	ctx := context.Background()

	auth1, err := client.Authenticate(ctx, &accountv1.AuthenticateRequest{
		Email: "user@example.com", Password: passphrase,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if auth1.GetKeysEnrolled() {
		t.Error("keys_enrolled should be false before EnrollKeys")
	}

	// Enrol the encryption keypair.
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	wrapped, err := e2e.WrapPrivateKey(passphrase, kp.Private)
	if err != nil {
		t.Fatalf("WrapPrivateKey: %v", err)
	}
	if _, err := client.EnrollKeys(withSession(auth1.GetSessionToken()), &accountv1.EnrollKeysRequest{
		PublicKey: kp.Public, WrappedPrivateKey: wrapped,
	}); err != nil {
		t.Fatalf("EnrollKeys: %v", err)
	}

	// coxswain issues a legacy per-user profile (the test connects directly, with
	// no relay fingerprint, so GetProfile falls back to the per-user profile).
	if _, err := profile.Issue(ctx, conn, userID, "", profile.Profile{FleetID: "fleet-1"}); err != nil {
		t.Fatalf("profile.Issue: %v", err)
	}

	resp, err := client.GetProfile(withSession(auth1.GetSessionToken()), &accountv1.GetProfileRequest{})
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if resp.GetRevision() != 1 {
		t.Errorf("revision: got %d want 1", resp.GetRevision())
	}

	// The device decrypts the bundle with its passphrase-unwrapped key.
	priv, err := e2e.UnwrapPrivateKey(passphrase, resp.GetWrappedPrivateKey())
	if err != nil {
		t.Fatalf("UnwrapPrivateKey: %v", err)
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(resp.GetCiphertext(), &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	plaintext, err := e2e.Open(bundle, priv, resp.GetSigningPublicKey())
	if err != nil {
		t.Fatalf("e2e.Open: %v", err)
	}
	var got profile.Profile
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if got.User != userID || got.FleetID != "fleet-1" {
		t.Errorf("decrypted profile mismatch: %+v", got)
	}
}

func TestAuthenticateBadPassword(t *testing.T) {
	client, _, _ := newService(t)
	_, err := client.Authenticate(context.Background(), &accountv1.AuthenticateRequest{
		Email: "user@example.com", Password: "wrong",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v want Unauthenticated", err)
	}
}

func TestGetProfileRequiresSession(t *testing.T) {
	client, _, _ := newService(t)
	_, err := client.GetProfile(context.Background(), &accountv1.GetProfileRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no session: got %v want Unauthenticated", err)
	}
	_, err = client.GetProfile(withSession("bogus-token"), &accountv1.GetProfileRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad session: got %v want Unauthenticated", err)
	}
}

func TestGetProfileNoneIssued(t *testing.T) {
	client, _, _ := newService(t)
	a, err := client.Authenticate(context.Background(), &accountv1.AuthenticateRequest{
		Email: "user@example.com", Password: passphrase,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_, err = client.GetProfile(withSession(a.GetSessionToken()), &accountv1.GetProfileRequest{})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v want NotFound", err)
	}
}
