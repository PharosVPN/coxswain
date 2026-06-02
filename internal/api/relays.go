// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"net"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
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
	// Host is the relay's IP/hostname (the endpoint minus its port), so the map
	// can merge a relay onto a node that shares the same box.
	Host string `json:"host"`
	// Egress / Onion report which control-plane roles this relay carries.
	Egress    bool   `json:"egress"`
	EgressHop int    `json:"egress_hop"`
	Onion     bool   `json:"onion"`
	ServerID  string `json:"server_id"`
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

func toRelayView(r fleet.Relay) relayView {
	return relayView{
		ID:        r.ID,
		Name:      r.Name,
		Kind:      r.Kind,
		Region:    r.Region,
		Status:    r.Status,
		Host:      relayHost(r),
		Egress:    r.EgressEndpoint != "",
		EgressHop: r.EgressHop,
		Onion:     r.OnionEndpoint != "" && r.OnionPubKey != "",
		ServerID:  r.ServerID,
	}
}

func (s *Server) handleListRelays(w http.ResponseWriter, r *http.Request) {
	relays, err := fleet.ListRelays(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list relays")
		return
	}
	views := make([]relayView, 0, len(relays))
	for _, rl := range relays {
		views = append(views, toRelayView(rl))
	}
	writeJSON(w, http.StatusOK, views)
}
