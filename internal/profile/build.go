// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile

import (
	"encoding/json"
	"net"
	"strconv"

	"github.com/PharosVPN/coxswain/internal/wg"
)

// ProtocolVersionAmneziaWG is the version tag for amneziawg protocol blocks.
const ProtocolVersionAmneziaWG = 2

// ProtocolVersionXRayReality is the version tag for xray-reality protocol blocks.
const ProtocolVersionXRayReality = 1

// ClientListenPort is the UDP port a node's client interface (awg0) is bound to
// — the port a caravel client must dial. The endpoint pool advertises this (one
// port, many IPs); the client picks a random IP and dials this port. (Decision
// 17's per-port rotation is not dialable while awg0 binds a single port, so the
// pool pins the real listen port instead of an aspirational range.)
const ClientListenPort = 443

// XRayListenPort is the TCP port a node's XRay/REALITY server binds — the port a
// caravel REALITY client dials. (TCP 443, distinct from AmneziaWG's UDP 443.)
const XRayListenPort = 443

// DefaultXRayFlow / DefaultXRayFingerprint are the REALITY client defaults: the
// xtls-rprx-vision flow and a Chrome uTLS fingerprint for the camouflage
// handshake.
const (
	DefaultXRayFlow        = "xtls-rprx-vision"
	DefaultXRayFingerprint = "chrome"
)

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
// the device's peer material on it. A node may offer AmneziaWG, XRay/REALITY,
// or both; an empty server public key for a protocol omits that protocol's
// entry for this node.
type BuildNode struct {
	ID          string
	Name        string
	Region      string
	EndpointIPs []string // the node's endpoint IP pool
	WGPublicKey string   // the node's AmneziaWG server public key ("" = no AmneziaWG entry)
	// PresharedKey is the per-(device,node) 256-bit PSK (decision 15).
	PresharedKey string
	AllowedIPs   []string
	// Obfuscation is the node's AmneziaWG obfuscation parameter set — the
	// client must apply the exact values to handshake (DESIGN §3).
	Obfuscation wg.Obfuscation
	// XRayPublicKey is the node's XRay/REALITY server public key ("" = no
	// XRay/REALITY entry for this node).
	XRayPublicKey string
}

// XRayClientPolicy is the fleet-wide REALITY camouflage the client presents:
// the decoy SNI, the REALITY shortId, and a uTLS fingerprint. Zero when XRay is
// disabled.
type XRayClientPolicy struct {
	ServerName  string // SNI the client presents — the decoy host
	ShortID     string // REALITY shortId (may be empty)
	Fingerprint string // uTLS fingerprint, e.g. "chrome"
	Flow        string // VLESS flow, e.g. "xtls-rprx-vision"
}

// BuildInput is everything needed to assemble a device's profile.
type BuildInput struct {
	User           string
	FleetID        string
	DeviceWGKey    string // the device's AmneziaWG private key
	DeviceXRayUUID string // the device's XRay/REALITY VLESS UUID
	TunnelIP       string // the device's allocated VPN address
	Rotation       RotationPolicy
	Nodes          []BuildNode
	// XRay is the fleet-wide REALITY client policy, applied to every node that
	// offers an XRay/REALITY entry. Zero when XRay is disabled.
	XRay XRayClientPolicy
	// Path is the device's egress chain (entry → [mid] → exit) for display, or
	// nil when the device egresses at a single node.
	Path *PathView
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

// xrayRealityParams is the params block of an xray-reality protocol entry —
// everything a caravel REALITY client needs: its VLESS identity (UUID + flow),
// the node's REALITY public key, the camouflage policy it presents, and the
// node's endpoint pool (TCP).
type xrayRealityParams struct {
	UUID        string         `json:"uuid"`
	Flow        string         `json:"flow"`
	Address     string         `json:"address"`
	PublicKey   string         `json:"public_key"`
	ServerName  string         `json:"server_name"`
	ShortID     string         `json:"short_id"`
	Fingerprint string         `json:"fingerprint"`
	Endpoints   []EndpointPool `json:"endpoints"`
	Rotation    RotationPolicy `json:"rotation"`
	AllowedIPs  []string       `json:"allowed_ips"`
}

// Build assembles a populated Profile from a device's peers. Revision and
// timestamps are filled in by Issue when the profile is sealed.
func Build(in BuildInput) Profile {
	p := Profile{FleetID: in.FleetID, User: in.User, Path: in.Path}
	// For a path-bound device the client dials only the entry node; the rest of
	// the chain (mids → exit) is routed server-side. Carry just the entry, so the
	// profile is what the client actually uses — one entry node plus the egress
	// path — not the whole fleet. (A single-node device carries all its nodes.)
	entryID := ""
	if in.Path != nil && len(in.Path.Hops) > 0 {
		entryID = in.Path.Hops[0].ID
	}
	for _, n := range in.Nodes {
		if entryID != "" && n.ID != entryID {
			continue
		}
		flat := append([]string(nil), n.EndpointIPs...)

		var protocols []Protocol
		// AmneziaWG entry (UDP). The pool pins the real listen port.
		if n.WGPublicKey != "" {
			pool := endpointPool(n.EndpointIPs, ClientListenPort)
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
			protocols = append(protocols, Protocol{
				Type:   ProtocolAmneziaWG,
				V:      ProtocolVersionAmneziaWG,
				Params: params,
			})
		}
		// XRay/REALITY entry (TCP). The client dials the same IP pool on the
		// REALITY TCP port and presents the fleet-wide camouflage policy.
		if n.XRayPublicKey != "" {
			pool := endpointPool(n.EndpointIPs, XRayListenPort)
			params, _ := json.Marshal(xrayRealityParams{
				UUID:        in.DeviceXRayUUID,
				Flow:        in.XRay.Flow,
				Address:     in.TunnelIP + "/32",
				PublicKey:   n.XRayPublicKey,
				ServerName:  in.XRay.ServerName,
				ShortID:     in.XRay.ShortID,
				Fingerprint: in.XRay.Fingerprint,
				Endpoints:   pool,
				Rotation:    in.Rotation,
				AllowedIPs:  n.AllowedIPs,
			})
			protocols = append(protocols, Protocol{
				Type:   ProtocolXRayReality,
				V:      ProtocolVersionXRayReality,
				Params: params,
			})
		}
		if len(protocols) == 0 {
			continue // node offers nothing this device can use
		}
		p.Nodes = append(p.Nodes, Node{
			ID:        n.ID,
			Name:      n.Name,
			Region:    n.Region,
			Endpoints: flat,
			Protocols: protocols,
		})
	}
	return p
}

// RealityCamouflage turns a configured decoy site into the REALITY dest
// (host:port) and the accepted serverNames (the decoy host). A bare host gets
// the default TLS port; an explicit host:port is preserved. Both the node's
// pushed config and the client profile must agree on these — this is the single
// source.
func RealityCamouflage(decoy string) (dest string, serverNames []string) {
	if host, _, err := net.SplitHostPort(decoy); err == nil {
		return decoy, []string{host}
	}
	return net.JoinHostPort(decoy, strconv.Itoa(XRayListenPort)), []string{decoy}
}

// endpointPool turns a node's IP list into a pinned-port endpoint pool.
func endpointPool(ips []string, port int) []EndpointPool {
	pool := make([]EndpointPool, 0, len(ips))
	for _, ip := range ips {
		pool = append(pool, EndpointPool{IP: ip, PortMin: port, PortMax: port})
	}
	return pool
}
