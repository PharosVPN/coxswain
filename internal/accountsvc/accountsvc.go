// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package accountsvc implements the AccountSync gRPC service (DESIGN §8) — the
// relayed client service that authenticates end users and serves their
// end-to-end-encrypted profile bundles. caravel reaches it through a relay
// relay; coxswain serves only ciphertext.
package accountsvc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/enroll"
	accountv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/account/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
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

// x25519KeySize is the byte length of an X25519 public key — the size the
// device's join-link encryption pubkey must be (Curve25519 point).
const x25519KeySize = 32

// ClaimConfig carries the controller-side dependencies ClaimEnrollment needs to
// turn a redeemed ticket + CSR into an enrolled, provisioned device and hand the
// device everything it needs to assemble its own bundle. It is optional: a
// Service built without it (SetClaimConfig never called) still serves the
// cert-authenticated RPCs, but ClaimEnrollment returns Unimplemented.
type ClaimConfig struct {
	// DeviceCA signs the device's CSR into its client leaf.
	DeviceCA pki.Authority
	// ProvisionOpts is the fleet policy ProvisionDevice applies (the egress
	// data-plane attach step).
	ProvisionOpts provision.Options
	// The fields the device pins to reach + verify the relay and bundles.
	FleetCAPEM       []byte // the Fleet CA the device pins to verify the relay leaf
	RelayAddr        string
	RelayServerName  string
	CAFingerprint    string
	SigningPublicKey []byte
}

// Service implements accountv1.AccountSyncServer.
type Service struct {
	accountv1.UnimplementedAccountSyncServer
	db    *sql.DB
	claim *ClaimConfig
}

// New builds the account/sync service.
func New(db *sql.DB) *Service {
	return &Service{db: db}
}

// SetClaimConfig enables the ClaimEnrollment RPC by supplying the device CA,
// provisioning policy, and the relay/bundle details the claimed device pins.
// Call before serving. Without it ClaimEnrollment is Unimplemented.
func (s *Service) SetClaimConfig(cfg ClaimConfig) { s.claim = &cfg }

// Authenticate verifies an account passphrase and opens a session.
// Authenticate opens a session. With no email it is cert-auth: the device proves
// who it is via its relay-verified leaf (the account passphrase never leaves the
// device — it is only used locally to unwrap the e2e key). With an email it is
// the legacy passphrase check. Either way it returns the user and whether the
// account has enrolled an encryption key.
func (s *Service) Authenticate(ctx context.Context, req *accountv1.AuthenticateRequest) (*accountv1.AuthenticateResponse, error) {
	var userID string
	if req.GetEmail() == "" {
		dev, ok := s.deviceFromFingerprint(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no credentials — present an enrolled device or an email")
		}
		userID = dev.UserID
	} else {
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
		userID = user.ID
	}

	token, err := auth.CreateSession(ctx, s.db, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "authentication failed")
	}
	pub, _, err := account.GetEncryptionKey(ctx, s.db, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "authentication failed")
	}
	return &accountv1.AuthenticateResponse{
		SessionToken: token,
		UserId:       userID,
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
//
// The bundle's sealing RECIPIENT differs by device, and so does what the device
// needs to open it:
//   - A per-device-keyed device (the passphrase-less join-link flow) has its
//     bundle sealed to its OWN X25519 key, which it already holds. The response
//     carries an EMPTY wrapped_private_key — there is nothing to unwrap.
//   - A legacy account-sync device's bundle is sealed to the user's account key,
//     so the response carries the user's passphrase-wrapped private key for the
//     device to unwrap locally with the account passphrase.
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

	// Only a device that decrypts with the ACCOUNT key needs the wrapped account
	// private key. A per-device-keyed device already holds its own key, so we omit
	// it (and never even read the account key for that device).
	var wrapped []byte
	if perDevice, derr := s.deviceHasOwnKey(ctx, deviceID); derr != nil {
		return nil, status.Error(codes.Internal, "failed to load profile")
	} else if !perDevice {
		if _, wrapped, err = account.GetEncryptionKey(ctx, s.db, userID); err != nil {
			return nil, status.Error(codes.Internal, "failed to load profile")
		}
	}

	return &accountv1.GetProfileResponse{
		Ciphertext:        ciphertext,
		Revision:          revision,
		SigningPublicKey:  signing.Public,
		WrappedPrivateKey: wrapped,
	}, nil
}

// deviceHasOwnKey reports whether the named device carries its own per-device
// X25519 encryption key (the passphrase-less join-link case), in which case its
// bundle is sealed to that key and the account wrapped-key is irrelevant. A
// blank deviceID (the legacy per-user caller) is never per-device.
func (s *Service) deviceHasOwnKey(ctx context.Context, deviceID string) (bool, error) {
	if deviceID == "" {
		return false, nil
	}
	dev, err := account.GetDevice(ctx, s.db, deviceID)
	if err != nil {
		return false, err
	}
	return dev.HasEncryptionKey(), nil
}

// ClaimEnrollment redeems a one-time enrollment ticket + a device-generated CSR
// into a fully enrolled, provisioned device, and returns everything the device
// needs to assemble its own .pharosid locally and sync.
//
// AUTHORIZATION — by TICKET, never by CERTIFICATE. Every other AccountSync RPC
// identifies its caller through the relay-forwarded device fingerprint
// (x-pharos-device-fp) or a session token. This one deliberately does NEITHER:
// the device has no Device-CA leaf yet (this RPC mints it), so it cannot present
// one, and the relay will allow a cert-less connection for just this method (a
// later relay change). The plaintext enrollment token is the sole credential —
// RedeemTicket validates and one-time-claims it. We never call s.caller()/the
// fingerprint path here; a fingerprint, if somehow present, is ignored.
//
// The flow separates DEVICE IDENTITY from EGRESS DATA-PLANE POLICY:
//  1. sign the CSR → the device's leaf + fingerprint (identity);
//  2. create the device → fleet membership keyed to that fingerprint (identity,
//     data-plane-agnostic);
//  3. ProvisionDevice → allocate the tunnel + node peers + seal the profile
//     (attach the egress data-plane policy — a mesh policy would slot in here).
func (s *Service) ClaimEnrollment(ctx context.Context, req *accountv1.ClaimEnrollmentRequest) (*accountv1.ClaimEnrollmentResponse, error) {
	if s.claim == nil {
		return nil, status.Error(codes.Unimplemented, "enrollment claim is not enabled on this controller")
	}
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "an enrollment token is required")
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "a device CSR is required")
	}
	// The join flow is passphrase-less: the device MUST present its own 32-byte
	// X25519 encryption public key, which coxswain seals the device's profile to
	// so the device decrypts with its own private half — no account passphrase.
	if len(req.GetEncryptionPubkey()) != x25519KeySize {
		return nil, status.Errorf(codes.InvalidArgument,
			"a %d-byte device encryption public key is required", x25519KeySize)
	}

	name := req.GetDeviceName()
	if name == "" {
		name = "caravel device"
	}
	platform := req.GetPlatform()
	if platform == "" {
		platform = "caravel"
	}

	// Sign the device leaf from the supplied CSR (the device keeps its key). A bad
	// or rogue-SAN CSR fails here with InvalidArgument — never a panic. The Subject
	// and SANs are assigned by SignDeviceCSR, not copied from the CSR.
	signed, err := pki.SignDeviceCSR(s.claim.DeviceCA, req.GetCsrPem(), name)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid device CSR: %v", err)
	}
	fingerprint := deviceFingerprint(signed.Cert.Raw)

	// Redeem the ticket FIRST and atomically (one-time guard) so a replayed token
	// cannot create a second device; only then do we commit the device + provision
	// against the user it names. used_by_device_id is stamped with the id we are
	// about to create, so the claim is auditable end-to-end.
	deviceID := account.NewDeviceID()
	ticket, err := enroll.RedeemTicket(ctx, s.db, req.GetToken(), deviceID)
	if errors.Is(err, enroll.ErrTicketInvalid) {
		s.auditClaim(ctx, "", deviceID, err)
		// Unauthenticated: the token is the credential, and it did not authenticate.
		return nil, status.Error(codes.Unauthenticated, "enrollment ticket invalid, expired, or already used")
	}
	if err != nil {
		s.auditClaim(ctx, "", deviceID, err)
		return nil, status.Error(codes.Internal, "failed to redeem enrollment ticket")
	}

	// (1) Device identity — fleet membership keyed to the leaf fingerprint, the
	// same value the relay forwards as x-pharos-device-fp. Data-plane-agnostic.
	device, err := account.CreateDevice(ctx, s.db, account.Device{
		ID:          deviceID,
		UserID:      ticket.UserID,
		Name:        name,
		Platform:    platform,
		Fingerprint: fingerprint,
		Status:      account.StatusActive,
		// The device's own X25519 encryption key — ProvisionDevice seals this
		// device's profile to it, so the device opens its bundle with no account
		// passphrase (the passphrase-less join-link flow).
		EncryptionPubkey: req.GetEncryptionPubkey(),
	})
	if err != nil {
		s.auditClaim(ctx, ticket.UserID, deviceID, err)
		return nil, status.Error(codes.Internal, "failed to create device")
	}

	// (2) Attach the egress data-plane policy — allocate the tunnel IP + per-node
	// peers and seal the device's profile. This is the separable step a future mesh
	// policy would replace/extend; device identity above does not depend on it.
	if _, err := provision.ProvisionDevice(ctx, s.db, device.ID, s.claim.ProvisionOpts); err != nil {
		// The device + claim are already committed; surface the failure but leave
		// the enrolled identity in place so a re-provision can heal it.
		s.auditClaim(ctx, ticket.UserID, device.ID, err)
		if errors.Is(err, profile.ErrNoEncryptionKey) {
			return nil, status.Error(codes.FailedPrecondition, "the account has not enrolled an encryption key yet")
		}
		return nil, status.Error(codes.Internal, "device enrolled but provisioning failed")
	}

	s.auditClaim(ctx, ticket.UserID, device.ID, nil)
	return &accountv1.ClaimEnrollmentResponse{
		DeviceCertPem:    signed.CertPEM,
		FleetCaPem:       s.claim.FleetCAPEM,
		RelayAddr:        s.claim.RelayAddr,
		RelayServerName:  s.claim.RelayServerName,
		CaFingerprint:    s.claim.CAFingerprint,
		SigningPublicKey: s.claim.SigningPublicKey,
	}, nil
}

// auditClaim records an enroll.claim event. actor is the enrolled user (empty
// when the ticket never resolved); target is the device id; the source IP comes
// from the gRPC peer (the relay/tunnel endpoint — we never trust client headers).
func (s *Service) auditClaim(ctx context.Context, userID, deviceID string, err error) {
	actor := userID
	if actor == "" {
		actor = "enrollment-ticket"
	}
	_ = audit.Log(ctx, s.db, audit.Entry{
		Actor:      actor,
		ActorKind:  audit.KindToken, // a one-time enrollment token, not a session/cert
		Action:     "enroll.claim",
		TargetType: "device",
		TargetID:   deviceID,
		SourceIP:   peerIP(ctx),
		Err:        err,
	})
}

// peerIP returns the gRPC peer's IP (the relay/tunnel endpoint), or "" — the
// trusted source for the audit trail, since client-set metadata is not trusted.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

// deviceFingerprint is the device-leaf fingerprint coxswain stores and the relay
// forwards: "sha256:" + hex(sha256(PEM(cert))). Must match the offline
// `.pharosid` flow (cli.deviceFingerprint) and relay/core.certFingerprint.
func deviceFingerprint(der []byte) string {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sum := sha256.Sum256(pemBytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// caller resolves who is calling. The relay-verified device fingerprint
// (x-pharos-device-fp) identifies the *device* (and thus its user), so sync
// returns that device's own profile. Without it (direct/legacy callers) it falls
// back to the session token, yielding the user with an empty device id (the
// legacy per-user profile).
func (s *Service) caller(ctx context.Context) (userID, deviceID string, err error) {
	if dev, ok := s.deviceFromFingerprint(ctx); ok {
		return dev.UserID, dev.ID, nil
	}
	uid, serr := s.authenticated(ctx)
	if serr != nil {
		return "", "", serr
	}
	return uid, "", nil
}

// deviceFromFingerprint resolves the calling device from the relay-forwarded,
// trusted x-pharos-device-fp metadata. ok is false when there is no fingerprint
// (a direct/legacy caller) or it names no enrolled device.
func (s *Service) deviceFromFingerprint(ctx context.Context) (account.Device, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return account.Device{}, false
	}
	fps := md.Get(deviceFPMetadataKey)
	if len(fps) == 0 || fps[0] == "" {
		return account.Device{}, false
	}
	dev, err := account.GetDeviceByFingerprint(ctx, s.db, fps[0])
	if err != nil {
		return account.Device{}, false
	}
	return dev, true
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
