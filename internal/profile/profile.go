// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package profile builds the VPN profiles coxswain issues to users, seals them
// end-to-end (DESIGN §8), and stores the ciphertext. The Profile structure is
// also the plaintext inside a `.pharos` account-mode file (DESIGN §9).
package profile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Protocol type tags (DESIGN §9 — versioned, ignore-unknown).
const (
	ProtocolAmneziaWG   = "amneziawg"
	ProtocolXRayReality = "xray-reality"
)

// Profile is a device's VPN configuration: the set of named profiles it may
// connect with. It is JSON-encoded, then sealed to the user (see Issue). One
// device holds several profiles (the rendered form of its profile_specs); a
// device with no specs gets auto-profiles spanning every ready node.
type Profile struct {
	FleetID   string          `json:"fleet_id"`
	User      string          `json:"user"`
	Revision  int64           `json:"revision"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Profiles  []ClientProfile `json:"profiles"`
}

// ClientProfile is one named connection config in a device's bundle — the
// rendered form of one admin profile (a profile_spec, or an auto-profile when a
// device has none). The client lists these and connects with exactly one. Each
// carries a single data-plane protocol; its nodes hold exactly that protocol's
// material (one entry node for a direct or cascade profile, every ready node for
// an auto-profile).
type ClientProfile struct {
	ID       string `json:"id"`       // profile_spec id, or "auto-<protocol>"
	Name     string `json:"name"`     // admin-given display name
	Protocol string `json:"protocol"` // ProtocolAmneziaWG | ProtocolXRayReality
	Nodes    []Node `json:"nodes"`    // entry node(s) the client may dial
	// Path is the multi-hop egress chain a cascade profile's traffic takes
	// (decision 18). Display metadata: the client dials the entry hop (also in
	// Nodes) and the controller routes entry → [mid] → exit. Nil for a direct
	// single-node egress.
	Path *PathView `json:"path,omitempty"`
}

// PathHop is one node in a device's egress chain, for client display. Hop 0 is
// the entry (the node the client dials), the last is the exit (where traffic
// leaves the fleet). The node id lets the client match the entry to a Node.
type PathHop struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Role   string   `json:"role"` // "entry", "mid", or "exit"
	IPs    []string `json:"ips"`
}

// PathView is the ordered egress chain a path-bound device's traffic takes.
type PathView struct {
	Name string    `json:"name"`
	Hops []PathHop `json:"hops"`
}

// Node is one VPN node in a profile.
type Node struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Region    string     `json:"region"`
	Endpoints []string   `json:"endpoints"`
	Protocols []Protocol `json:"protocols"`
}

// Protocol is a versioned, tagged data-plane protocol. Clients keep a registry
// keyed by Type and skip any Type they do not recognise (DESIGN §11).
type Protocol struct {
	Type   string          `json:"type"`
	V      int             `json:"v"`
	Params json.RawMessage `json:"params"`
}

// GeneratePresharedKey returns a fresh 256-bit AmneziaWG preshared key in the
// base64 form WireGuard expects (DESIGN §4, decision 15).
func GeneratePresharedKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("profile: crypto/rand unavailable: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}
