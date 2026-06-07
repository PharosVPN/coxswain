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

// BuildInput is everything needed to render one client profile from a profile
// spec (or an auto-profile).
type BuildInput struct {
	SpecID string // the profile_spec id, or "auto-<protocol>"
	Name   string // the profile's display name
	// Protocol is the single data-plane protocol this profile carries
	// (ProtocolAmneziaWG or ProtocolXRayReality); only that protocol's entry is
	// emitted for each node.
	Protocol       string
	DeviceWGKey    string // the profile's AmneziaWG private key
	DeviceXRayUUID string // the profile's XRay/REALITY VLESS UUID
	TunnelIP       string // the profile's allocated VPN address
	Rotation       RotationPolicy
	Nodes          []BuildNode
	// XRay is the fleet-wide REALITY client policy, applied to every node that
	// offers an XRay/REALITY entry. Zero when XRay is disabled.
	XRay XRayClientPolicy
	// Path is the profile's egress chain (entry → [mid] → exit) for display, or
	// nil when the profile egresses at a single node.
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

// BuildClientProfile renders one client profile from a spec's resolved nodes and
// the profile's own credentials. Only in.Protocol's entry is emitted on each
// node — a profile carries a single data-plane protocol. A node that does not
// offer that protocol is dropped. For a cascade profile (Path set) only the
// entry hop is carried; the rest of the chain is routed server-side.
func BuildClientProfile(in BuildInput) ClientProfile {
	cp := ClientProfile{ID: in.SpecID, Name: in.Name, Protocol: in.Protocol, Path: in.Path, MTU: pathMTU(in.Path)}
	// For a path-bound profile the client dials only the entry node; the rest of
	// the chain (mids → exit) is routed server-side. Carry just the entry, so the
	// profile is what the client actually uses. (A direct profile carries its
	// single node; an auto-profile carries every ready node.)
	entryID := ""
	if in.Path != nil && len(in.Path.Hops) > 0 {
		entryID = in.Path.Hops[0].ID
	}
	for _, n := range in.Nodes {
		if entryID != "" && n.ID != entryID {
			continue
		}
		flat := append([]string(nil), n.EndpointIPs...)

		// A "both" profile carries both protocol entries on each node; the client
		// chooses at connect. A single-protocol profile emits only its own.
		emitAWG := in.Protocol == ProtocolAmneziaWG || in.Protocol == ProtocolBoth
		emitXRay := in.Protocol == ProtocolXRayReality || in.Protocol == ProtocolBoth

		var protocols []Protocol
		if emitAWG {
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
		}
		if emitXRay {
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
		}
		if len(protocols) == 0 {
			continue // node does not offer this profile's protocol
		}
		cp.Nodes = append(cp.Nodes, Node{
			ID:        n.ID,
			Name:      n.Name,
			Region:    n.Region,
			Endpoints: flat,
			Protocols: protocols,
		})
	}
	return cp
}

// innerLinkOverhead is the bytes one inner AmneziaWG cascade layer (entry→exit)
// costs a client packet. Each cascade hop decaps the client's tunnel and recaps
// it for the next link; that re-encapsulation eats headroom, so the client's
// tunnel MTU must shrink by this much per inner link or large packets blackhole.
// 80B is a CONSERVATIVE estimate (AmneziaWG/WireGuard framing + IPv6 headroom);
// the EXACT value must be re-verified against a real multi-hop client connect —
// the live cascade data path could not be measured without a connected client.
// Observed: a 2-node path's inner link ran at MTU 1340 (= 1420 - 80), which this
// formula reproduces.
const innerLinkOverhead = 80

// minSaneMTU is an absurdity floor (the IPv4 minimum reassembly buffer). The
// hop-aware formula is conservative and is intentionally NOT clamped UP toward
// 1420 — clamping up would reintroduce the blackhole. This floor only guards
// against a pathological hop count producing a sub-576 MTU.
const minSaneMTU = 576

// pathMTU returns the conservative tunnel MTU for a profile's egress path, or 0
// (the 1420 client default) for a direct single-node profile. A cascade packet
// is re-encapsulated once per inner link (entry→exit), so the client's MTU must
// drop by innerLinkOverhead per inner link to fit each inner AWG link:
//
//	mtu = 1420 - 80*innerLinks,  innerLinks = max(1, len(Hops)-1)
//
// A 2-node path → 1340 (matches the observed inner link); a 4-node path → 1180.
// We never clamp UP (that would blackhole again); only an absurd result below
// minSaneMTU is floored.
func pathMTU(path *PathView) int {
	if path == nil || len(path.Hops) == 0 {
		return 0 // direct profile: leave unset, client defaults to 1420
	}
	innerLinks := len(path.Hops) - 1
	if innerLinks < 1 {
		innerLinks = 1
	}
	mtu := defaultClientMTU - innerLinkOverhead*innerLinks
	if mtu < minSaneMTU {
		mtu = minSaneMTU
	}
	return mtu
}

// defaultClientMTU is the client's tunnel MTU on a direct (single-hop) profile —
// the AmneziaWG client interface (awg0) MTU. The hop-aware cascade MTU reduces
// from this baseline.
const defaultClientMTU = 1420

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
