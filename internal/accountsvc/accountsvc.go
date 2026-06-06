// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package accountsvc implements the AccountSync gRPC service (DESIGN §8) — the
// relayed client service that authenticates end users and serves their
// end-to-end-encrypted profile bundles. caravel reaches it through a relay
// relay; coxswain serves only ciphertext.
package accountsvc

import (
	"context"
	"database/sql"
	"errors"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/profile"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// sessionMetadataKey carries the session token on authenticated RPCs.
const sessionMetadataKey = "pharos-session"

// deviceFPMetadataKey is the relay-verified device fingerprint (the device's
// Device-CA leaf), forwarded by the relay after it terminates the device's mTLS.
// A client cannot set it — the relay strips client-supplied x-pharos-* keys — so
// coxswain trusts it to identify the calling device. Must match the relay
// (relay/core.deviceFPMetadataKey) and the pki/relay fingerprint shape.
const deviceFPMetadataKey = "x-pharos-device-fp"

// Service implements accountv1.AccountSyncServer.
type Service struct {
	accountv1.UnimplementedAccountSyncServer
	db *sql.DB
}

// New builds the account/sync service.
func New(db *sql.DB) *Service {
	return &Service{db: db}
}

// Authenticate verifies an account passphrase and opens a session.
func (s *Service) Authenticate(ctx context.Context, req *accountv1.AuthenticateRequest) (*accountv1.AuthenticateResponse, error) {
	user, err := account.GetUserByEmail(ctx, s.db, req.GetEmail())
	if errors.Is(err, account.ErrNotFound) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "authentication failed")
	}
	if user.Status != account.StatusActive || !auth.VerifyPassword(user.PasswordHash, req.GetPassword()) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	token, err := auth.CreateSession(ctx, s.db, user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "authentication failed")
	}
	pub, _, err := account.GetEncryptionKey(ctx, s.db, user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "authentication failed")
	}
	return &accountv1.AuthenticateResponse{
		SessionToken: token,
		UserId:       user.ID,
		KeysEnrolled: len(pub) > 0,
	}, nil
}

// EnrollKeys registers a user's encryption keypair on first device setup.
func (s *Service) EnrollKeys(ctx context.Context, req *accountv1.EnrollKeysRequest) (*accountv1.EnrollKeysResponse, error) {
	userID, _, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.GetPublicKey()) == 0 || len(req.GetWrappedPrivateKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "public key and wrapped private key are required")
	}
	if err := account.SetEncryptionKey(ctx, s.db, userID, req.GetPublicKey(), req.GetWrappedPrivateKey()); err != nil {
		return nil, status.Error(codes.Internal, "failed to enrol keys")
	}
	return &accountv1.EnrollKeysResponse{}, nil
}

// GetProfile returns the calling device's latest sealed profile bundle. When the
// relay forwards the device fingerprint, this is the device's own profile (its
// keys + path); otherwise it falls back to the legacy per-user profile.
func (s *Service) GetProfile(ctx context.Context, _ *accountv1.GetProfileRequest) (*accountv1.GetProfileResponse, error) {
	userID, deviceID, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}

	ciphertext, revision, err := profile.LatestCiphertext(ctx, s.db, userID, deviceID)
	if errors.Is(err, profile.ErrNoProfile) {
		if deviceID != "" {
			return nil, status.Error(codes.NotFound, "no profile provisioned for this device yet")
		}
		return nil, status.Error(codes.NotFound, "no profile issued for this account")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load profile")
	}
	signing, _, err := profile.EnsureSigningKey(ctx, s.db)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load profile")
	}
	_, wrapped, err := account.GetEncryptionKey(ctx, s.db, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load profile")
	}
	return &accountv1.GetProfileResponse{
		Ciphertext:        ciphertext,
		Revision:          revision,
		SigningPublicKey:  signing.Public,
		WrappedPrivateKey: wrapped,
	}, nil
}

// caller resolves who is calling. The relay-verified device fingerprint
// (x-pharos-device-fp) identifies the *device* (and thus its user), so sync
// returns that device's own profile. Without it (direct/legacy callers) it falls
// back to the session token, yielding the user with an empty device id (the
// legacy per-user profile).
func (s *Service) caller(ctx context.Context) (userID, deviceID string, err error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if fps := md.Get(deviceFPMetadataKey); len(fps) > 0 && fps[0] != "" {
			if dev, derr := account.GetDeviceByFingerprint(ctx, s.db, fps[0]); derr == nil {
				return dev.UserID, dev.ID, nil
			}
			// Unknown fingerprint — the device may not be enrolled. Fall through
			// to the session rather than hard-failing.
		}
	}
	uid, serr := s.authenticated(ctx)
	if serr != nil {
		return "", "", serr
	}
	return uid, "", nil
}

// authenticated resolves the session token from request metadata to a user ID.
func (s *Service) authenticated(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "not authenticated")
	}
	tokens := md.Get(sessionMetadataKey)
	if len(tokens) == 0 {
		return "", status.Error(codes.Unauthenticated, "not authenticated")
	}
	userID, err := auth.ResolveSession(ctx, s.db, tokens[0])
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "session invalid or expired")
	}
	return userID, nil
}
