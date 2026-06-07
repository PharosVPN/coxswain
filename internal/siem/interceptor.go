// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package siem

import (
	"context"
	"database/sql"
	"strings"

	"github.com/PharosVPN/coxswain/internal/authn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ctxKey is the unexported context key type for the authenticated token.
type ctxKey struct{}

// TokenFromContext returns the authenticated token stashed by the auth
// interceptor, or false if none (e.g. on an unauthenticated path).
func TokenFromContext(ctx context.Context) (authn.Token, bool) {
	t, ok := ctx.Value(ctxKey{}).(authn.Token)
	return t, ok
}

// AuthInterceptor returns a gRPC StreamServerInterceptor that authenticates the
// caller from the "authorization: Bearer cox_..." metadata, requires monitor
// scope, and stashes the resolved token in the stream context. It rejects:
//   - missing/empty/invalid credentials with codes.Unauthenticated
//   - a valid token whose scope is below monitor with codes.PermissionDenied
//
// db is the same handle authn.Authenticate uses to resolve the token.
func AuthInterceptor(db *sql.DB) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		secret, err := bearerFromContext(ss.Context())
		if err != nil {
			return err
		}
		tok, aErr := authn.Authenticate(ss.Context(), db, secret)
		if aErr != nil {
			// Any auth failure (unknown, expired, revoked, empty) is Unauthenticated
			// — we deliberately do not leak which, matching the HTTP plane.
			return status.Error(codes.Unauthenticated, "invalid or expired token")
		}
		if !tok.Allows(authn.ScopeMonitor) {
			return status.Error(codes.PermissionDenied, "monitor scope required")
		}
		// Wrap the stream so the handler sees the authenticated context.
		wrapped := &authedStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), ctxKey{}, tok)}
		return handler(srv, wrapped)
	}
}

// bearerFromContext extracts the "cox_"-prefixed bearer secret from the incoming
// gRPC metadata's authorization header. A missing/malformed header is
// Unauthenticated.
func bearerFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing credentials")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	const prefix = "Bearer "
	h := vals[0]
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", status.Error(codes.Unauthenticated, "authorization must be a Bearer token")
	}
	secret := strings.TrimSpace(h[len(prefix):])
	if secret == "" {
		return "", status.Error(codes.Unauthenticated, "empty bearer token")
	}
	return secret, nil
}

// authedStream is a grpc.ServerStream that overrides Context() so the handler
// receives the auth-enriched context.
type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (a *authedStream) Context() context.Context { return a.ctx }
