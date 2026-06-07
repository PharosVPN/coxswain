// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/auth"
)

// anonymousActor is the audit actor for unauthenticated/failed actions, so an
// attacker-supplied value never lands in the actor column (log-injection guard).
const anonymousActor = "<anonymous>"

// maxDetailField caps an attacker-controlled value before it is stored in the
// structured (JSON-encoded) detail blob, so a giant submitted username can't
// bloat the audit row.
const maxDetailField = 256

// secureCookie reports whether the session cookie should carry the Secure
// attribute for this request. It is set when the request arrived over TLS, or —
// only when a trusted TLS-terminating proxy is declared (ui.behind_tls_proxy) —
// when X-Forwarded-Proto says https. The SSH-tunnel-over-http-loopback workflow
// still works: browsers don't send Secure cookies over http://localhost, so the
// flag stays off there and the cookie is accepted.
func (s *Server) secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.behindTLSProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// userView is the API representation of a user — never includes the hash.
type userView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Role    string `json:"role"`
	Status  string `json:"status"`
	Version int    `json:"version"`
}

func toUserView(u account.User) userView {
	return userView{ID: u.ID, Name: u.Name, Email: u.Email, Phone: u.Phone, Role: u.Role, Status: u.Status, Version: u.Version}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := account.GetUserByEmail(r.Context(), s.db, req.Username)
	if errors.Is(err, account.ErrNotFound) {
		s.auditLoginFailed(r, req.Username, "no such account")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	// M5: only admins use the web UI.
	if user.Status != account.StatusActive ||
		user.Role != account.RoleAdmin ||
		!auth.VerifyPassword(user.PasswordHash, req.Password) {
		s.auditLoginFailed(r, req.Username, "invalid credentials")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := auth.CreateSession(r.Context(), s.db, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	_ = audit.Log(r.Context(), s.db, audit.Entry{
		Actor: user.Email, ActorKind: audit.KindSession, Action: "auth.login",
		TargetType: "user", TargetID: user.ID, SourceIP: audit.SourceIP(r),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.SessionTTL / time.Second),
	})
	writeJSON(w, http.StatusOK, toUserView(user))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = auth.DeleteSession(r.Context(), s.db, cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	// LOW-12: record the logout. The session is resolved by the auth middleware,
	// so the actor is the admin (not attacker-controlled).
	s.audited(r, "auth.logout", "user", currentUser(r).ID, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toUserView(currentUser(r)))
}

// auditLoginFailed records a failed login attempt (result=error). LOW-13: the
// actor is a fixed anonymous marker — the submitted username is attacker
// controlled, so it goes (length-capped) into the structured detail blob, which
// is JSON-encoded + escaped, never into the actor column where it could be used
// for log injection/confusion.
func (s *Server) auditLoginFailed(r *http.Request, username, reason string) {
	if len(username) > maxDetailField {
		username = username[:maxDetailField]
	}
	_ = audit.Log(r.Context(), s.db, audit.Entry{
		Actor: anonymousActor, ActorKind: audit.KindSession, Action: "auth.login_failed",
		TargetType: "user", SourceIP: audit.SourceIP(r),
		Detail: map[string]any{"username": username},
		Err:    errors.New(reason),
	})
}
