// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"encoding/json"

	"github.com/PharosVPN/coxswain/internal/wg"
)

// ProtocolVersionAmneziaWG is the version tag for amneziawg protocol blocks.
const ProtocolVersionAmneziaWG = 2

// EndpointPool is one node IP and the UDP port range it accepts AmneziaWG on.
// The client picks a random port in [PortMin, PortMax] (decision 17).
type EndpointPool struct {
	IP      string `json:"ip"`
	PortMin int    `json:"port_min"`
	PortMax int    `json:"port_max"`
}

// RotationPolicy tells the client how to rotate its endpoint (decision 17).
type RotationPolicy struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
	JitterSeconds   int  `json:"jitter_seconds"`
}

// BuildNode is one node's contribution to a profile — the node identity plus
// the device's peer material on it.
type BuildNode struct {
	ID          string
	Name        string
	Region      string
	EndpointIPs []string // the node's endpoint IP pool
	WGPublicKey string   // the node's AmneziaWG server public key
	// PresharedKey is the per-(device,node) 256-bit PSK (decision 15).
	PresharedKey string
	AllowedIPs   []string
	// Obfuscation is the node's AmneziaWG obfuscation parameter set — the
	// client must apply the exact values to handshake (DESIGN §3).
	Obfuscation wg.Obfuscation
}

// BuildInput is everything needed to assemble a device's profile.
type BuildInput struct {
	User        string
	FleetID     string
	DeviceWGKey string // the device's AmneziaWG private key
	TunnelIP    string // the device's allocated VPN address
	PortMin     int    // endpoint UDP port range
	PortMax     int
	Rotation    RotationPolicy
	Nodes       []BuildNode
}

// amneziaWGParams is the params block of an amneziawg protocol entry.
type amneziaWGParams struct {
	PrivateKey   string         `json:"private_key"`
	Address      string         `json:"address"`
	PublicKey    string         `json:"public_key"`
	PresharedKey string         `json:"preshared_key"`
	Endpoints    []EndpointPool `json:"endpoints"`
	Rotation     RotationPolicy `json:"rotation"`
	AllowedIPs   []string       `json:"allowed_ips"`
	// Obfuscation is the node's AmneziaWG obfuscation parameter set.
	Obfuscation wg.Obfuscation `json:"obfuscation"`
}

// Build assembles a populated Profile from a device's peers. Revision and
// timestamps are filled in by Issue when the profile is sealed.
func Build(in BuildInput) Profile {
	p := Profile{FleetID: in.FleetID, User: in.User}
	for _, n := range in.Nodes {
		pool := make([]EndpointPool, 0, len(n.EndpointIPs))
		flat := make([]string, 0, len(n.EndpointIPs))
		for _, ip := range n.EndpointIPs {
			pool = append(pool, EndpointPool{IP: ip, PortMin: in.PortMin, PortMax: in.PortMax})
			flat = append(flat, ip)
		}
		params, _ := json.Marshal(amneziaWGParams{
			PrivateKey:   in.DeviceWGKey,
			Address:      in.TunnelIP + "/32",
			PublicKey:    n.WGPublicKey,
			PresharedKey: n.PresharedKey,
			Endpoints:    pool,
			Rotation:     in.Rotation,
			AllowedIPs:   n.AllowedIPs,
			Obfuscation:  n.Obfuscation,
		})
		p.Nodes = append(p.Nodes, Node{
			ID:        n.ID,
			Name:      n.Name,
			Region:    n.Region,
			Endpoints: flat,
			Protocols: []Protocol{{
				Type:   ProtocolAmneziaWG,
				V:      ProtocolVersionAmneziaWG,
				Params: params,
			}},
		})
	}
	return p
}
