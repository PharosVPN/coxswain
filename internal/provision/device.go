// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package provision places a user's device onto the fleet: it allocates the
// device a tunnel address and a peer (keypair + preshared key) on every
// ready node, then issues a sealed profile (DESIGN §8, §9).
package provision

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/wg"
	"github.com/google/uuid"
)

// Options carries the fleet settings provisioning needs (from the config).
type Options struct {
	VPNSubnet string
	PortMin   int
	PortMax   int
	Rotation  profile.RotationPolicy
	// XRay enables placing an XRay/REALITY client alongside AmneziaWG on every
	// node that has reported a REALITY public key.
	XRay XRayOptions
	// Control is the geo-located control-plane endpoint (the relay the client
	// syncs through), carried into the bundle for the client's map. Zero when
	// the controller location is unknown.
	Control profile.ControlEndpoint
}

// XRayOptions is the fleet-wide XRay/REALITY provisioning policy.
type XRayOptions struct {
	Enabled    bool
	ServerName string // the REALITY decoy SNI the client presents (Reality.DecoySite)
	ShortID    string // the REALITY shortId (may be empty)
}

// Result reports what ProvisionDevice produced.
type Result struct {
	Device account.Device
	// TunnelIP is the first provisioned profile's tunnel address (representative;
	// each profile now has its own).
	TunnelIP       string
	PeerCount      int
	ProfileCount   int
	ProfileVersion int64
}

// ProvisionDevice renders every profile a device should hold into its own
// credentials + node peers, then issues one freshly sealed bundle carrying them
// all. A device's profiles are its profile_specs; a device with no specs gets
// auto-profiles spanning every ready node (one per available protocol), which
// preserves the pre-profiles behaviour. Each profile is minted independently:
// its own tunnel IP, its own AmneziaWG keypair or VLESS UUID, and peers tagged
// with the spec id (auto-profiles are untagged). A node is "ready" for a
// protocol once it has reported that protocol's server identity and a public
// address.
//
// The peer records are coxswain's desired state; pushing them to nodes over the
// control channel is the control loop's job.
func ProvisionDevice(ctx context.Context, db *sql.DB, deviceID string, opts Options) (Result, error) {
	device, err := account.GetDevice(ctx, db, deviceID)
	if err != nil {
		return Result{}, err
	}
	nodes, err := fleet.ListNodes(ctx, db)
	if err != nil {
		return Result{}, err
	}
	byID := make(map[string]fleet.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	specs, err := fleet.ListProfileSpecsByDevice(ctx, db, device.ID)
	if err != nil {
		return Result{}, err
	}

	// Idempotent per device: remember each profile's existing tunnel IP (keyed by
	// spec id; "" for the auto-profiles) so a re-provision keeps it — a fresh IP
	// would orphan a cascade fwmark — then clear all peers so they don't
	// accumulate. New keys/UUIDs are fine: the device re-fetches the bundle.
	existing, err := fleet.ListPeersByDevice(ctx, db, device.ID)
	if err != nil {
		return Result{}, err
	}
	ipBySpec := map[string]string{}
	for _, p := range existing {
		if ipBySpec[p.ProfileSpecID] == "" && p.AllowedIP != "" {
			ipBySpec[p.ProfileSpecID] = p.AllowedIP
		}
	}
	if len(existing) > 0 {
		if _, err := fleet.DeletePeersByDevice(ctx, db, device.ID); err != nil {
			return Result{}, fmt.Errorf("provision: clear old peers: %w", err)
		}
	}

	var (
		clientProfiles []profile.ClientProfile
		peerCount      int
		firstIP        string
	)
	if len(specs) == 0 {
		cps, n, ip, err := provisionAuto(ctx, db, device, nodes, ipBySpec[""], opts)
		if err != nil {
			return Result{}, err
		}
		clientProfiles, peerCount, firstIP = cps, n, ip
	} else {
		for _, spec := range specs {
			cp, n, ip, err := provisionSpec(ctx, db, device, spec, byID, ipBySpec[spec.ID], opts)
			if err != nil {
				return Result{}, err
			}
			clientProfiles = append(clientProfiles, cp)
			peerCount += n
			if firstIP == "" {
				firstIP = ip
			}
		}
	}

	prof := profile.Profile{User: device.UserID, Profiles: clientProfiles}
	if opts.Control != (profile.ControlEndpoint{}) {
		ctrl := opts.Control
		prof.Control = &ctrl
	}
	revision, err := profile.Issue(ctx, db, device.UserID, device.ID, prof)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Device:         device,
		TunnelIP:       firstIP,
		PeerCount:      peerCount,
		ProfileCount:   len(clientProfiles),
		ProfileVersion: revision,
	}, nil
}

// provisionSpec mints one profile spec into the device's own credentials and an
// entry peer, and renders its client profile. The client always dials a single
// entry — the spec's node (direct) or the path's entry hop (cascade); a cascade
// profile additionally carries the egress chain for display, and is wired into
// the inner-link routing separately by the cascade coordinator.
func provisionSpec(ctx context.Context, db *sql.DB, device account.Device, spec fleet.ProfileSpec, byID map[string]fleet.Node, reuseIP string, opts Options) (profile.ClientProfile, int, string, error) {
	var (
		entry    fleet.Node
		pathView *profile.PathView
	)
	if spec.NodeID != "" {
		var ok bool
		if entry, ok = byID[spec.NodeID]; !ok {
			return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: no such node %s", spec.ID, spec.NodeID)
		}
	} else {
		pv, ent, err := pathViewForPath(ctx, db, spec.PathID, byID)
		if err != nil {
			return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: %w", spec.ID, err)
		}
		pathView, entry = pv, ent
	}
	if len(entry.EndpointAddrs()) == 0 {
		return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: entry node %s has no public address", spec.ID, entry.ID)
	}

	tunnelIP, err := tunnelIP(ctx, db, reuseIP, opts)
	if err != nil {
		return profile.ClientProfile{}, 0, "", err
	}

	bn := profile.BuildNode{
		ID:          entry.ID,
		Name:        entry.Name,
		Region:      entry.Region,
		EndpointIPs: entryIPs(entry, spec.EntryIPs),
		AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
	}
	// A "both" profile mints both an AmneziaWG and an XRay/REALITY peer on the
	// entry (sharing one tunnel IP), so the client can dial the entry with either;
	// the cascade beyond the entry is always AmneziaWG regardless. The data-plane
	// protocol only ever describes the client↔entry hop.
	wantAWG := spec.Protocol == fleet.ProtoAmneziaWG || spec.Protocol == fleet.ProtoBoth
	wantXRay := spec.Protocol == fleet.ProtoXRayReality || spec.Protocol == fleet.ProtoBoth
	var (
		wgKey, xrayUUID string
		peerCount       int
	)

	if wantAWG {
		if entry.WGPublicKey == "" || entry.Obfuscation.IsZero() {
			return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: entry node %s is not AmneziaWG-ready", spec.ID, entry.ID)
		}
		keys, err := wg.GenerateKeyPair()
		if err != nil {
			return profile.ClientProfile{}, 0, "", err
		}
		psk := profile.GeneratePresharedKey()
		if _, err := fleet.CreatePeer(ctx, db, fleet.Peer{
			NodeID:        entry.ID,
			DeviceID:      device.ID,
			Protocol:      profile.ProtocolAmneziaWG,
			PublicKey:     keys.PublicKey,
			AllowedIP:     tunnelIP,
			PresharedKey:  psk,
			ProfileSpecID: spec.ID,
		}); err != nil {
			return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s amneziawg peer: %w", spec.ID, err)
		}
		wgKey = keys.PrivateKey
		bn.WGPublicKey = entry.WGPublicKey
		bn.PresharedKey = psk
		bn.Obfuscation = entry.Obfuscation
		peerCount++
	}

	if wantXRay {
		xrayReady := opts.XRay.Enabled && entry.XRayPublicKey != ""
		switch {
		case xrayReady:
			xrayUUID = uuid.NewString()
			if _, err := fleet.CreatePeer(ctx, db, fleet.Peer{
				NodeID:        entry.ID,
				DeviceID:      device.ID,
				Protocol:      profile.ProtocolXRayReality,
				PublicKey:     xrayUUID,
				AllowedIP:     tunnelIP,
				Flow:          profile.DefaultXRayFlow,
				ProfileSpecID: spec.ID,
			}); err != nil {
				return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s xray peer: %w", spec.ID, err)
			}
			bn.XRayPublicKey = entry.XRayPublicKey
			peerCount++
		case spec.Protocol == fleet.ProtoXRayReality:
			// An XRay-only profile needs the entry to actually offer REALITY.
			return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: entry node %s is not XRay-ready", spec.ID, entry.ID)
			// else: a "both" profile on an entry without REALITY → AmneziaWG only.
		}
	}

	if peerCount == 0 {
		return profile.ClientProfile{}, 0, "", fmt.Errorf("provision: spec %s: entry node %s offers neither protocol", spec.ID, entry.ID)
	}

	cp := profile.BuildClientProfile(profile.BuildInput{
		SpecID:         spec.ID,
		Name:           spec.Name,
		Protocol:       spec.Protocol,
		DeviceWGKey:    wgKey,
		DeviceXRayUUID: xrayUUID,
		TunnelIP:       tunnelIP,
		Rotation:       opts.Rotation,
		Nodes:          []profile.BuildNode{bn},
		XRay:           clientPolicy(opts),
		Path:           pathView,
	})
	return cp, peerCount, tunnelIP, nil
}

// provisionAuto renders the auto-profiles a device with no specs receives: one
// AmneziaWG profile and (when XRay is enabled) one XRay/REALITY profile, each
// spanning every ready node and sharing a single tunnel IP/keypair/UUID — the
// pre-profiles behaviour, reshaped into the profiles[] bundle. A device bound to
// a path (legacy device_exits) carries the egress chain on its auto-profiles.
func provisionAuto(ctx context.Context, db *sql.DB, device account.Device, nodes []fleet.Node, reuseIP string, opts Options) ([]profile.ClientProfile, int, string, error) {
	ip, err := tunnelIP(ctx, db, reuseIP, opts)
	if err != nil {
		return nil, 0, "", err
	}
	keys, err := wg.GenerateKeyPair()
	if err != nil {
		return nil, 0, "", err
	}
	xrayUUID := uuid.NewString()

	var awgNodes, xrayNodes []profile.BuildNode
	peerCount := 0
	for _, n := range nodes {
		if len(n.EndpointAddrs()) == 0 {
			continue // node has no public address yet
		}
		awgReady := n.WGPublicKey != "" && !n.Obfuscation.IsZero()
		xrayReady := opts.XRay.Enabled && n.XRayPublicKey != ""
		base := profile.BuildNode{
			ID:          n.ID,
			Name:        n.Name,
			Region:      n.Region,
			EndpointIPs: n.EndpointAddrs(),
			AllowedIPs:  []string{"0.0.0.0/0", "::/0"},
		}
		if awgReady {
			psk := profile.GeneratePresharedKey()
			if _, err := fleet.CreatePeer(ctx, db, fleet.Peer{
				NodeID:       n.ID,
				DeviceID:     device.ID,
				Protocol:     profile.ProtocolAmneziaWG,
				PublicKey:    keys.PublicKey,
				AllowedIP:    ip,
				PresharedKey: psk,
			}); err != nil {
				return nil, 0, "", fmt.Errorf("provision: amneziawg peer on %s: %w", n.ID, err)
			}
			bn := base
			bn.WGPublicKey = n.WGPublicKey
			bn.PresharedKey = psk
			bn.Obfuscation = n.Obfuscation
			awgNodes = append(awgNodes, bn)
			peerCount++
		}
		if xrayReady {
			if _, err := fleet.CreatePeer(ctx, db, fleet.Peer{
				NodeID:    n.ID,
				DeviceID:  device.ID,
				Protocol:  profile.ProtocolXRayReality,
				PublicKey: xrayUUID,
				AllowedIP: ip,
				Flow:      profile.DefaultXRayFlow,
			}); err != nil {
				return nil, 0, "", fmt.Errorf("provision: xray peer on %s: %w", n.ID, err)
			}
			bn := base
			bn.XRayPublicKey = n.XRayPublicKey
			xrayNodes = append(xrayNodes, bn)
			peerCount++
		}
	}

	pathView, err := buildPathView(ctx, db, device.ID, nodes)
	if err != nil {
		return nil, 0, "", err
	}

	var cps []profile.ClientProfile
	if len(awgNodes) > 0 {
		cps = append(cps, profile.BuildClientProfile(profile.BuildInput{
			SpecID:      "auto-" + profile.ProtocolAmneziaWG,
			Name:        "All Nodes (AmneziaWG)",
			Protocol:    profile.ProtocolAmneziaWG,
			DeviceWGKey: keys.PrivateKey,
			TunnelIP:    ip,
			Rotation:    opts.Rotation,
			Nodes:       awgNodes,
			Path:        pathView,
		}))
	}
	if len(xrayNodes) > 0 {
		cps = append(cps, profile.BuildClientProfile(profile.BuildInput{
			SpecID:         "auto-" + profile.ProtocolXRayReality,
			Name:           "All Nodes (XRay/REALITY)",
			Protocol:       profile.ProtocolXRayReality,
			DeviceXRayUUID: xrayUUID,
			TunnelIP:       ip,
			Rotation:       opts.Rotation,
			Nodes:          xrayNodes,
			XRay:           clientPolicy(opts),
			Path:           pathView,
		}))
	}
	return cps, peerCount, ip, nil
}

// tunnelIP reuses a profile's existing address (idempotent re-provision) or
// allocates the next free one.
func tunnelIP(ctx context.Context, db *sql.DB, reuse string, opts Options) (string, error) {
	if reuse != "" {
		return reuse, nil
	}
	return fleet.AllocateDeviceIP(ctx, db, opts.VPNSubnet)
}

// entryIPs narrows a node's endpoint pool to the spec's allowed subset, or
// returns the whole pool when the spec lists none. Unknown IPs in the subset are
// ignored; an empty intersection falls back to the full pool so a profile is
// never left undialable.
func entryIPs(node fleet.Node, subset []string) []string {
	all := node.EndpointAddrs()
	if len(subset) == 0 {
		return all
	}
	want := make(map[string]bool, len(subset))
	for _, ip := range subset {
		want[ip] = true
	}
	var out []string
	for _, ip := range all {
		if want[ip] {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// clientPolicy is the fleet-wide REALITY camouflage applied to XRay profiles.
func clientPolicy(opts Options) profile.XRayClientPolicy {
	return profile.XRayClientPolicy{
		ServerName:  xrayServerName(opts.XRay.ServerName),
		ShortID:     opts.XRay.ShortID,
		Fingerprint: profile.DefaultXRayFingerprint,
		Flow:        profile.DefaultXRayFlow,
	}
}

// xrayServerName normalises the configured decoy to the bare SNI host the
// REALITY client must present (the node's accepted serverName), stripping any
// port so it agrees with the node's pushed config.
func xrayServerName(decoy string) string {
	_, serverNames := profile.RealityCamouflage(decoy)
	if len(serverNames) > 0 {
		return serverNames[0]
	}
	return decoy
}

// buildPathView assembles a device's egress chain from its legacy device_exits
// binding (the per-device cascade), or returns nil when the device is not bound
// to a path (normal single-node egress). Used only for auto-profiles; spec
// profiles carry their own path via pathViewForPath.
func buildPathView(ctx context.Context, db *sql.DB, deviceID string, nodes []fleet.Node) (*profile.PathView, error) {
	de, err := fleet.GetDeviceExit(ctx, db, deviceID)
	if errors.Is(err, fleet.ErrNotFound) {
		return nil, nil // no cascade binding — normal single-node egress
	}
	if err != nil {
		return nil, fmt.Errorf("provision: device exit: %w", err)
	}
	byID := make(map[string]fleet.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	view, _, err := pathViewForPath(ctx, db, de.PathID, byID)
	return view, err
}

// pathViewForPath assembles a path's egress chain for a profile's display
// metadata and returns the entry node (hop 0 — the node the client dials). The
// last hop is the exit where traffic leaves the fleet (decision 18).
func pathViewForPath(ctx context.Context, db *sql.DB, pathID string, byID map[string]fleet.Node) (*profile.PathView, fleet.Node, error) {
	p, err := fleet.GetPath(ctx, db, pathID)
	if err != nil {
		return nil, fleet.Node{}, fmt.Errorf("path %s: %w", pathID, err)
	}
	hops, err := fleet.ListPathHops(ctx, db, pathID)
	if err != nil {
		return nil, fleet.Node{}, fmt.Errorf("path %s hops: %w", pathID, err)
	}
	if len(hops) == 0 {
		return nil, fleet.Node{}, fmt.Errorf("path %s has no hops", pathID)
	}
	view := &profile.PathView{Name: p.Name}
	for i, h := range hops {
		role := "mid"
		switch {
		case i == 0:
			role = "entry"
		case i == len(hops)-1:
			role = "exit"
		}
		n := byID[h.NodeID]
		view.Hops = append(view.Hops, profile.PathHop{
			ID:     h.NodeID,
			Name:   n.Name,
			Region: n.Region,
			Role:   role,
			IPs:    n.EndpointAddrs(),
		})
	}
	return view, byID[hops[0].NodeID], nil
}
