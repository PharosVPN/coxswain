// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
)

// minPasswordLen is the minimum length for a UI-created admin password.
const minPasswordLen = 8

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	users, err := account.ListUsersByRole(r.Context(), s.db, account.RoleAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list admins")
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, toUserView(u))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if len(req.Password) < minPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create admin")
		return
	}
	user, err := account.CreateUser(r.Context(), s.db, account.User{
		Email:        req.Email,
		Role:         account.RoleAdmin,
		PasswordHash: hash,
	})
	if errors.Is(err, account.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "email already in use")
		return
	}
	if err != nil {
		s.audited(r, "admin.add", "user", "", map[string]any{"email": req.Email}, err)
		writeError(w, http.StatusInternalServerError, "failed to create admin")
		return
	}
	s.audited(r, "admin.add", "user", user.ID, map[string]any{"email": user.Email}, nil)
	writeJSON(w, http.StatusCreated, toUserView(user))
}

// handleDeleteAdmin removes an admin. The built-in admin (config-driven) and
// the caller's own account cannot be deleted.
func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == account.FixedAdminID {
		writeError(w, http.StatusForbidden, "the built-in admin cannot be deleted")
		return
	}
	if id == currentUser(r).ID {
		writeError(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	err := account.DeleteUser(r.Context(), s.db, id)
	if errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "admin not found")
		return
	}
	if err != nil {
		s.audited(r, "admin.rm", "user", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete admin")
		return
	}
	s.audited(r, "admin.rm", "user", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
