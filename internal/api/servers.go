// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

// handleSSHKey returns coxswain's public SSH key in authorized_keys format, so
// the admin can add it as a login key when creating a machine — then onboard it
// with `--key` (no password).
func (s *Server) handleSSHKey(w http.ResponseWriter, r *http.Request) {
	id, _, err := ssh.EnsureIdentity(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load SSH key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": id.AuthorizedKey})
}

// locate resolves a host IP to a location for the map/cards, or nil when the
// geoip database is unavailable or the IP can't be placed.
func (s *Server) locate(host string) *geoip.Location {
	if loc, ok := s.geo.Lookup(host); ok {
		return &loc
	}
	return nil
}

// Deployer onboards servers (machines) and deploys node/relay roles onto them.
// It is implemented in the CLI layer (serve.go), which holds the CA, SSH
// identity, and egress dialer the API package deliberately doesn't import.
type Deployer interface {
	// Bootstrap SSHes in with the one-time password, installs cox's key, and
	// records the server. The password is used once and never stored.
	Bootstrap(ctx context.Context, req BootstrapRequest) (fleet.Server, error)
	DeployNode(ctx context.Context, serverID, name, region string) (fleet.Node, error)
	DeployRelay(ctx context.Context, serverID string, req RelayDeployRequest) (fleet.Relay, error)
}

// BootstrapRequest is the POST /api/servers body.
type BootstrapRequest struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	Host     string `json:"ssh_host"`
	User     string `json:"ssh_user"`
	Port     int    `json:"ssh_port"`
	Password string `json:"password"`
}

// RelayDeployRequest carries the relay-specific options for a deploy.
type RelayDeployRequest struct {
	Name       string
	Region     string
	Egress     bool
	Onion      bool
	EgressPort int
	OnionPort  int
}

type serverView struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Region   string          `json:"region"`
	SSHHost  string          `json:"ssh_host"`
	IsSelf   bool            `json:"is_self"`
	Status   string          `json:"status"`
	Location *geoip.Location `json:"location,omitempty"`
	Version  int             `json:"version"`
}

func (s *Server) serverView(srv fleet.Server) serverView {
	return serverView{
		ID:       srv.ID,
		Name:     srv.Name,
		Region:   srv.Region,
		SSHHost:  srv.SSHHost,
		IsSelf:   srv.IsSelf,
		Status:   srv.Status,
		Location: s.locate(srv.SSHHost),
		Version:  srv.Version,
	}
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := fleet.ListServers(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list servers")
		return
	}
	views := make([]serverView, 0, len(servers))
	for _, srv := range servers {
		views = append(views, s.serverView(srv))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	if s.deployer == nil {
		writeError(w, http.StatusServiceUnavailable, "server onboarding unavailable")
		return
	}
	var req BootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	srv, err := s.deployer.Bootstrap(r.Context(), req)
	req.Password = "" // scrub: never retained beyond the bootstrap call
	if err != nil {
		writeError(w, http.StatusBadGateway, "onboard failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.serverView(srv))
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	err := fleet.DeleteServer(r.Context(), s.db, r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if errors.Is(err, fleet.ErrServerInUse) {
		writeError(w, http.StatusConflict, "server still has deployed components")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete server")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeployServer(w http.ResponseWriter, r *http.Request) {
	if s.deployer == nil {
		writeError(w, http.StatusServiceUnavailable, "component deploy unavailable")
		return
	}
	var req struct {
		Role       string `json:"role"`
		Name       string `json:"name"`
		Region     string `json:"region"`
		Egress     bool   `json:"egress"`
		Onion      bool   `json:"onion"`
		EgressPort int    `json:"egress_port"`
		OnionPort  int    `json:"onion_port"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := r.PathValue("id")
	switch req.Role {
	case "node":
		node, err := s.deployer.DeployNode(r.Context(), id, req.Name, req.Region)
		if err != nil {
			writeError(w, http.StatusBadGateway, "deploy node failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, s.nodeView(node))
	case "relay":
		relay, err := s.deployer.DeployRelay(r.Context(), id, RelayDeployRequest{
			Name:       req.Name,
			Region:     req.Region,
			Egress:     req.Egress,
			Onion:      req.Onion,
			EgressPort: req.EgressPort,
			OnionPort:  req.OnionPort,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, "deploy relay failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, s.relayView(relay))
	default:
		writeError(w, http.StatusBadRequest, "role must be \"node\" or \"relay\"")
	}
}
