// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/authn"
)

type ctxKey int

const (
	userCtxKey ctxKey = iota
	tokenCtxKey
)

// authResult is what authenticate resolves a request to: exactly one of a
// session user or an API token. The middleware stores both (and the audit
// actor) on the request context for handlers.
type authResult struct {
	user  account.User // set for a session-cookie request
	token *authn.Token // set for a bearer-token request
}

// scope is the effective privilege of the authenticated caller. A session admin
// is treated as full admin (the existing behaviour); a token carries its own
// scope.
func (a authResult) scope() authn.Scope {
	if a.token != nil {
		return a.token.Scope
	}
	return authn.ScopeAdmin
}

// actor builds the audit actor for the request.
func (a authResult) actor() audit.Actor {
	if a.token != nil {
		return audit.Actor{Name: a.token.Name, Kind: audit.KindToken}
	}
	name := a.user.Email
	if name == "" {
		name = a.user.Name
	}
	return audit.Actor{Name: name, Kind: audit.KindSession}
}

// authenticate resolves the request's credentials: a valid cox_session cookie
// OR an Authorization: Bearer cox_... token. It returns the resolved caller, or
// an error with the HTTP status + message the caller should return.
func (s *Server) authenticate(r *http.Request) (authResult, int, string) {
	// Bearer token takes precedence when present, so a programmatic client is
	// never silently downgraded to a stale cookie.
	if secret, ok := bearerToken(r); ok {
		tok, err := authn.Authenticate(r.Context(), s.db, secret)
		switch {
		case errors.Is(err, authn.ErrInvalidToken):
			return authResult{}, http.StatusUnauthorized, "invalid token"
		case errors.Is(err, authn.ErrTokenExpired):
			return authResult{}, http.StatusUnauthorized, "token expired"
		case errors.Is(err, authn.ErrTokenRevoked):
			return authResult{}, http.StatusUnauthorized, "token revoked"
		case err != nil:
			return authResult{}, http.StatusUnauthorized, "token authentication failed"
		}
		return authResult{token: &tok}, 0, ""
	}

	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return authResult{}, http.StatusUnauthorized, "not authenticated"
	}
	userID, err := auth.ResolveSession(r.Context(), s.db, cookie.Value)
	if err != nil {
		return authResult{}, http.StatusUnauthorized, "session invalid or expired"
	}
	user, err := account.GetUser(r.Context(), s.db, userID)
	if err != nil {
		return authResult{}, http.StatusUnauthorized, "account not found"
	}
	if user.Status != account.StatusActive {
		return authResult{}, http.StatusForbidden, "account disabled"
	}
	if user.Role != account.RoleAdmin {
		return authResult{}, http.StatusForbidden, "admin access required"
	}
	return authResult{user: user}, 0, ""
}

// bearerToken extracts a "cox_"-prefixed bearer secret from the Authorization
// header, if present.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	secret := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	if !strings.HasPrefix(secret, "cox_") {
		return "", false
	}
	return secret, true
}

// requireAuth wraps a handler so it runs only for an authenticated caller — a
// session-cookie admin OR a valid bearer token (of any scope). The resolved
// caller and audit actor are placed on the request context.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.requireScope(authn.ScopeReadonly, next)
}

// requireScope wraps a handler so it runs only for an authenticated caller whose
// privilege is at least min. A session admin satisfies any scope (existing
// behaviour); a token must carry a scope that ranks >= min, else 403. The
// resolved caller and audit actor are placed on the request context.
func (s *Server) requireScope(min authn.Scope, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, status, msg := s.authenticate(r)
		if status != 0 {
			writeError(w, status, msg)
			return
		}
		if res.token != nil && !res.token.Allows(min) {
			writeError(w, http.StatusForbidden, "token scope "+string(res.token.Scope)+" is insufficient for this action")
			return
		}
		ctx := r.Context()
		if res.token != nil {
			ctx = context.WithValue(ctx, tokenCtxKey, res.token)
		} else {
			ctx = context.WithValue(ctx, userCtxKey, res.user)
		}
		ctx = audit.WithActor(ctx, res.actor())
		next(w, r.WithContext(ctx))
	}
}

// currentUser returns the session user placed by the auth middleware. For a
// token-authenticated request this is the zero User — handlers that depend on a
// session user (e.g. "can't delete your own account") are admin-scoped and the
// guard is benign for tokens.
func currentUser(r *http.Request) account.User {
	u, _ := r.Context().Value(userCtxKey).(account.User)
	return u
}
