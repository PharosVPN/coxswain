// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
)

type ctxKey int

const userCtxKey ctxKey = iota

// requireAuth wraps a handler so it runs only for an authenticated admin. The
// resolved user is placed in the request context. For M5 the whole admin API
// is admin-only — end-user logins arrive with M6.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		userID, err := auth.ResolveSession(r.Context(), s.db, cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session invalid or expired")
			return
		}
		user, err := account.GetUser(r.Context(), s.db, userID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "account not found")
			return
		}
		if user.Status != account.StatusActive {
			writeError(w, http.StatusForbidden, "account disabled")
			return
		}
		if user.Role != account.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, user)))
	}
}

// currentUser returns the authenticated user placed by requireAuth.
func currentUser(r *http.Request) account.User {
	u, _ := r.Context().Value(userCtxKey).(account.User)
	return u
}
