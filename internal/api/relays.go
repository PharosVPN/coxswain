// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/agentver"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
)

// relayView is the API representation of a relay for the admin map: where it is,
// what roles it plays (egress chain, onion hop), and the host it shares with a
// node when co-located.
type relayView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Region string `json:"region"`
	Status string `json:"status"`
	// AgentVersion is the relay build deployed on this relay (mirrors the node
	// view). Empty for the embedded relay and until first recorded. VersionDisplay
	// / AvailableVersion are the human forms; UpdateAvailable is true only when the
	// configured candidate relay binary is strictly newer than the deployed build.
	AgentVersion     string `json:"agent_version"`
	VersionDisplay   string `json:"version_display"`
	AvailableVersion string `json:"available_version"`
	UpdateAvailable  bool   `json:"update_available"`
	// Host is the relay's IP/hostname (the endpoint minus its port), so the map
	// can merge a relay onto a node that shares the same box.
	Host string `json:"host"`
	// Egress / Onion report which control-plane roles this relay carries.
	Egress    bool            `json:"egress"`
	EgressHop int             `json:"egress_hop"`
	Onion     bool            `json:"onion"`
	ServerID  string          `json:"server_id"`
	Location  *geoip.Location `json:"location,omitempty"`
}

func hostOf(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// relayHost is the relay's host for the map — whichever endpoint it has, so an
// egress/onion-only relay (no ingress) still lands on its city and merges onto a
// co-located node.
func relayHost(r fleet.Relay) string {
	for _, ep := range []string{r.Endpoint, r.EgressEndpoint, r.OnionEndpoint} {
		if h := hostOf(ep); h != "" {
			return h
		}
	}
	return ""
}

func (s *Server) relayView(r fleet.Relay, available string) relayView {
	return relayView{
		ID:               r.ID,
		Name:             r.Name,
		Kind:             r.Kind,
		Region:           r.Region,
		Status:           r.Status,
		AgentVersion:     r.AgentVersion,
		VersionDisplay:   agentver.Display(r.AgentVersion),
		AvailableVersion: agentver.Display(available),
		UpdateAvailable:  agentver.UpdateAvailable(r.AgentVersion, available),
		Host:             relayHost(r),
		Egress:           r.EgressEndpoint != "",
		EgressHop:        r.EgressHop,
		Onion:            r.OnionEndpoint != "" && r.OnionPubKey != "",
		ServerID:         r.ServerID,
		Location:         s.locate(relayHost(r)),
	}
}

func (s *Server) handleListRelays(w http.ResponseWriter, r *http.Request) {
	relays, err := fleet.ListRelays(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list relays")
		return
	}
	available := s.availableRelayVersion()
	views := make([]relayView, 0, len(relays))
	for _, rl := range relays {
		views = append(views, s.relayView(rl, available))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleDeleteRelay removes a relay from the fleet (the dashboard's Remove
// action). Like node removal, this drops coxswain's record; it does not uninstall
// the remote agent.
func (s *Server) handleDeleteRelay(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := fleet.DeleteRelay(r.Context(), s.db, id)
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "relay not found")
		return
	}
	if err != nil {
		s.audited(r, "relay.rm", "relay", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete relay")
		return
	}
	s.audited(r, "relay.rm", "relay", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateRelayAgent re-installs the configured relay binary on a remote
// relay in place — the dashboard's Update action. Returns the refreshed relay.
func (s *Server) handleUpdateRelayAgent(w http.ResponseWriter, r *http.Request) {
	if s.deployer == nil {
		writeError(w, http.StatusServiceUnavailable, "component deploy unavailable")
		return
	}
	id := r.PathValue("id")
	if _, err := fleet.GetRelay(r.Context(), s.db, id); errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "relay not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load relay")
		return
	}
	updated, err := s.deployer.UpdateRelayAgent(r.Context(), id)
	if err != nil {
		s.audited(r, "relay.update-agent", "relay", id, nil, err)
		writeError(w, http.StatusBadGateway, "update failed: "+err.Error())
		return
	}
	s.audited(r, "relay.update-agent", "relay", id, map[string]any{"agent_version": updated.AgentVersion}, nil)
	writeJSON(w, http.StatusOK, s.relayView(updated, s.availableRelayVersion()))
}
