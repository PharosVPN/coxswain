// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"errors"
	"fmt"
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

// selfView is the controller's own marker for the map: its public IP and the
// location resolved from it (nil when undetected / not placeable yet).
type selfView struct {
	PublicIP string          `json:"public_ip"`
	Location *geoip.Location `json:"location,omitempty"`
	Name     string          `json:"name"`
	Status   string          `json:"status"`
}

func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request) {
	v := selfView{PublicIP: s.controllerHost, Name: "controller", Status: "active"}
	if s.controllerHost != "" {
		v.Location = s.locate(s.controllerHost)
	}
	if self, err := fleet.GetSelfServer(r.Context(), s.db); err == nil {
		v.Name = self.Name
		v.Status = self.Status
	}
	writeJSON(w, http.StatusOK, v)
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
	// Route is the ordered relay-id hops to onboard (and later reach) this server
	// through; empty = direct (the default).
	Route []string `json:"route"`
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
	Route    []string        `json:"route"`
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
		Route:    srv.Route,
		Location: s.locate(srv.SSHHost),
		Version:  srv.Version,
	}
}

// handleSetServerRoute replaces a server's provision route — the ordered relay
// hops it is reached through (empty = direct) — without re-onboarding. The
// change applies to subsequent onboard/deploy SSH and node control-plane dials.
func (s *Server) handleSetServerRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := fleet.GetServer(r.Context(), s.db, id); errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "server not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	var req struct {
		Route []string `json:"route"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := fleet.SetServerRoute(r.Context(), s.db, id, req.Route); err != nil {
		s.audited(r, "server.route", "server", id, map[string]any{"route": req.Route, "hops": len(req.Route)}, err)
		writeError(w, http.StatusInternalServerError, "failed to set route")
		return
	}
	s.audited(r, "server.route", "server", id, map[string]any{"route": req.Route, "hops": len(req.Route)}, nil)
	srv, err := fleet.GetServer(r.Context(), s.db, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload server")
		return
	}
	writeJSON(w, http.StatusOK, s.serverView(srv))
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
	host := req.Host
	srv, err := s.deployer.Bootstrap(r.Context(), req)
	req.Password = "" // scrub: never retained beyond the bootstrap call
	if err != nil {
		s.audited(r, "server.add", "server", "", map[string]any{"ssh_host": host}, err)
		writeError(w, http.StatusBadGateway, "onboard failed: "+err.Error())
		return
	}
	s.audited(r, "server.add", "server", srv.ID, map[string]any{"name": srv.Name}, nil)
	writeJSON(w, http.StatusCreated, s.serverView(srv))
}

// handleDeleteServer forgets a server from the inventory, cascading to the
// node/relay roles recorded on it — so a server whose machine is already gone
// can be cleaned up in one action. It does not touch software on the host (a
// record-only removal, matching node removal). The controller's own host
// (is_self) cannot be removed.
func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	srv, err := fleet.GetServer(ctx, s.db, id)
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load server")
		return
	}
	if srv.IsSelf {
		writeError(w, http.StatusConflict, "cannot remove the controller's own host")
		return
	}

	// Block while any node on this server still carries client traffic — the
	// admin re-routes/re-provisions those clients first (no silent breakage).
	nodes, err := fleet.ListNodes(ctx, s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load nodes")
		return
	}
	impacted := 0
	for _, n := range nodes {
		if n.ServerID != id {
			continue
		}
		if c, err := fleet.CountClientsThroughNode(ctx, s.db, n.ID); err == nil {
			impacted += c
		}
	}
	if impacted > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("%d client(s) route through node(s) on this server — re-route or re-provision them first", impacted))
		return
	}

	// Cascade: drop the components recorded on this server first.
	for _, n := range nodes {
		if n.ServerID == id {
			_ = fleet.DeleteNode(ctx, s.db, n.ID)
		}
	}
	if relays, err := fleet.ListRelays(ctx, s.db); err == nil {
		for _, rl := range relays {
			if rl.ServerID == id {
				_ = fleet.DeleteRelay(ctx, s.db, rl.ID)
			}
		}
	}

	if err := fleet.DeleteServer(ctx, s.db, id); err != nil && !errors.Is(err, fleet.ErrNotFound) {
		s.audited(r, "server.rm", "server", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete server")
		return
	}
	s.audited(r, "server.rm", "server", id, map[string]any{"name": srv.Name}, nil)
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
			s.audited(r, "node.add", "server", id, map[string]any{"name": req.Name, "region": req.Region}, err)
			writeError(w, http.StatusBadGateway, "deploy node failed: "+err.Error())
			return
		}
		s.audited(r, "node.add", "node", node.ID, map[string]any{"name": node.Name, "server_id": id}, nil)
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
			s.audited(r, "relay.add", "server", id, map[string]any{"name": req.Name, "region": req.Region}, err)
			writeError(w, http.StatusBadGateway, "deploy relay failed: "+err.Error())
			return
		}
		s.audited(r, "relay.add", "relay", relay.ID, map[string]any{"name": relay.Name, "server_id": id}, nil)
		writeJSON(w, http.StatusCreated, s.relayView(relay))
	default:
		writeError(w, http.StatusBadRequest, "role must be \"node\" or \"relay\"")
	}
}
