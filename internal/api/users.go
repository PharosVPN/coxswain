// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
)

// handleListUsers lists end-user accounts (role "user"). Admins are listed
// separately by /api/admins.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := account.ListUsersByRole(r.Context(), s.db, account.RoleUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, toUserView(u))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreateUser creates an end-user account. The user enrols their own E2E
// encryption key later, from their passphrase (DESIGN §8).
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// A password is optional — a sync-only user authenticates by their device's
	// leaf (cert-auth), not a passphrase. If one is set (for the legacy email
	// login or the admin web), it must be long enough.
	var hash string
	if req.Password != "" {
		if len(req.Password) < minPasswordLen {
			writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
			return
		}
		h, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create user")
			return
		}
		hash = h
	}
	user, err := account.CreateUser(r.Context(), s.db, account.User{
		Name:         req.Name,
		Email:        req.Email,
		Phone:        req.Phone,
		Role:         account.RoleUser,
		PasswordHash: hash,
	})
	if errors.Is(err, account.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "email or phone already in use")
		return
	}
	if err != nil {
		s.audited(r, "user.add", "user", "", map[string]any{"name": req.Name, "email": req.Email}, err)
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	s.audited(r, "user.add", "user", user.ID, map[string]any{"name": user.Name, "email": user.Email}, nil)
	writeJSON(w, http.StatusCreated, toUserView(user))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := account.DeleteUser(r.Context(), s.db, id)
	if errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		s.audited(r, "user.rm", "user", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	s.audited(r, "user.rm", "user", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
