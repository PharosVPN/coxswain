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
)

// Options carries the fleet settings provisioning needs (from the config).
type Options struct {
	VPNSubnet string
	PortMin   int
	PortMax   int
	Rotation  profile.RotationPolicy
}

// Result reports what ProvisionDevice produced.
type Result struct {
	Device         account.Device
	TunnelIP       string
	PeerCount      int
	ProfileVersion int64
}

// ProvisionDevice gives a device a tunnel address and an AmneziaWG peer on
// every ready node, records the peers, and issues a freshly sealed profile to
// the device's owner. A node is "ready" once it has reported its WG public
// key and has a public address.
//
// The peer records are coxswain's desired state; pushing them to node over the
// control channel is the control loop's job.
func ProvisionDevice(ctx context.Context, db *sql.DB, deviceID string, opts Options) (Result, error) {
	device, err := account.GetDevice(ctx, db, deviceID)
	if err != nil {
		return Result{}, err
	}

	keys, err := wg.GenerateKeyPair()
	if err != nil {
		return Result{}, err
	}

	// Idempotent per device: re-provisioning keeps the device's existing tunnel
	// IP (a fresh one would orphan its cascade fwmark and leave the entry routing
	// a stale source into the inner link) and clears the old peer set first, so
	// peers don't accumulate across re-provisions. New WG keys are fine — the
	// device re-fetches the profile.
	existing, err := fleet.ListPeersByDevice(ctx, db, device.ID)
	if err != nil {
		return Result{}, err
	}
	var tunnelIP string
	if len(existing) > 0 {
		tunnelIP = existing[0].AllowedIP
		if _, err := fleet.DeletePeersByDevice(ctx, db, device.ID); err != nil {
			return Result{}, fmt.Errorf("provision: clear old peers: %w", err)
		}
	} else {
		tunnelIP, err = fleet.AllocateDeviceIP(ctx, db, opts.VPNSubnet)
		if err != nil {
			return Result{}, err
		}
	}

	nodes, err := fleet.ListNodes(ctx, db)
	if err != nil {
		return Result{}, err
	}

	var buildNodes []profile.BuildNode
	for _, n := range nodes {
		if n.WGPublicKey == "" || n.Obfuscation.IsZero() || len(n.EndpointAddrs()) == 0 {
			continue // node has not reported its data-plane config yet
		}
		psk := profile.GeneratePresharedKey()
		if _, err := fleet.CreatePeer(ctx, db, fleet.Peer{
			NodeID:       n.ID,
			DeviceID:     device.ID,
			Protocol:     profile.ProtocolAmneziaWG,
			PublicKey:    keys.PublicKey,
			AllowedIP:    tunnelIP,
			PresharedKey: psk,
		}); err != nil {
			return Result{}, fmt.Errorf("provision: peer on %s: %w", n.ID, err)
		}
		buildNodes = append(buildNodes, profile.BuildNode{
			ID:           n.ID,
			Name:         n.Name,
			Region:       n.Region,
			EndpointIPs:  n.EndpointAddrs(),
			WGPublicKey:  n.WGPublicKey,
			PresharedKey: psk,
			AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
			Obfuscation:  n.Obfuscation,
		})
	}

	pathView, err := buildPathView(ctx, db, device.ID, nodes)
	if err != nil {
		return Result{}, err
	}

	prof := profile.Build(profile.BuildInput{
		User:        device.UserID,
		DeviceWGKey: keys.PrivateKey,
		TunnelIP:    tunnelIP,
		PortMin:     opts.PortMin,
		PortMax:     opts.PortMax,
		Rotation:    opts.Rotation,
		Nodes:       buildNodes,
		Path:        pathView,
	})
	revision, err := profile.Issue(ctx, db, device.UserID, device.ID, prof)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Device:         device,
		TunnelIP:       tunnelIP,
		PeerCount:      len(buildNodes),
		ProfileVersion: revision,
	}, nil
}

// buildPathView assembles the device's egress chain for the profile's display
// metadata, or returns nil when the device is not bound to a path (it egresses
// at a single node). Hop 0 is the entry the client dials; the last is the exit
// where traffic leaves the fleet (decision 18).
func buildPathView(ctx context.Context, db *sql.DB, deviceID string, nodes []fleet.Node) (*profile.PathView, error) {
	de, err := fleet.GetDeviceExit(ctx, db, deviceID)
	if errors.Is(err, fleet.ErrNotFound) {
		return nil, nil // no cascade binding — normal single-node egress
	}
	if err != nil {
		return nil, fmt.Errorf("provision: device exit: %w", err)
	}
	p, err := fleet.GetPath(ctx, db, de.PathID)
	if err != nil {
		return nil, fmt.Errorf("provision: path %s: %w", de.PathID, err)
	}
	hops, err := fleet.ListPathHops(ctx, db, de.PathID)
	if err != nil {
		return nil, fmt.Errorf("provision: path hops: %w", err)
	}
	byID := make(map[string]fleet.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
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
	return view, nil
}
