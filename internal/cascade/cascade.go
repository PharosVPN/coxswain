// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package cascade coordinates node cascade / multi-hop (DESIGN §3, decision 18).
// coxswain is the sole mesh coordinator: it provisions entry→exit inner links
// and binds a device's traffic to egress through a chosen exit, driving both
// nodes over the existing control plane.
//
// The entry node policy-routes a cascaded device into the inner link (no SNAT —
// the literal transit rule); the exit node sees the entry as an ordinary
// forwarded+masqueraded peer whose AllowedIPs accumulate the cascaded devices'
// tunnel addresses. A device only ever handshakes with, and holds credentials
// for, its entry — never the exit.
package cascade

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
)

const (
	// awgClientPort is the UDP port a node's client interface (awg0) listens on;
	// the entry dials the exit there for the inner link (DESIGN §3).
	awgClientPort = 443
	// innerLinkMTU is the inner interface MTU: the client MTU (1420) less one
	// AmneziaWG encapsulation. It stays above the IPv6 floor for a 2-hop path.
	innerLinkMTU = 1340
	// mtuFloor is the minimum end-to-end MTU a cascade path may have (DESIGN §3).
	mtuFloor = 1280
	// rpcTimeout bounds each control-plane call to a node.
	rpcTimeout = 10 * time.Second
)

// ErrMTUTooLow is returned when a cascade path would drop below the MTU floor.
var ErrMTUTooLow = errors.New("cascade: path MTU below the 1280 floor")

// NodeClient is the subset of the control client cascade drives. *control.Client
// satisfies it; tests substitute a fake.
type NodeClient interface {
	ConfigureInnerLink(ctx context.Context, cfg *nodev1.InnerLinkConfig, revision int64) (*nodev1.ConfigureInnerLinkResponse, error)
	RemoveInnerLink(ctx context.Context, iface string) (*nodev1.RemoveInnerLinkResponse, error)
	AddPeer(ctx context.Context, peer *nodev1.Peer) (*nodev1.PeerResponse, error)
	RemovePeer(ctx context.Context, protocol nodev1.Protocol, publicKey string) (*nodev1.PeerResponse, error)
	SetNetworkConfig(ctx context.Context, forwarding, masquerade, isolation bool, transits []*nodev1.TransitRoute) (*nodev1.SetNetworkConfigResponse, error)
	Close() error
}

// DialFunc dials a node's control address and returns a client.
type DialFunc func(addr string) (NodeClient, error)

// Coordinator orchestrates cascade provisioning against the fleet database and
// the nodes' control plane.
type Coordinator struct {
	db   *sql.DB
	dial DialFunc
}

// New returns a Coordinator.
func New(db *sql.DB, dial DialFunc) *Coordinator {
	return &Coordinator{db: db, dial: dial}
}

// ProvisionLink creates an entry→exit edge and configures the entry's inner
// AmneziaWG interface toward the exit. The exit-side peer and per-device
// transit routes are wired when a device binds (BindExit), so a fresh link
// carries no traffic until then.
func (c *Coordinator) ProvisionLink(ctx context.Context, entryID, exitID string) (fleet.NodeLink, error) {
	entry, exit, err := c.edgeNodes(ctx, entryID, exitID)
	if err != nil {
		return fleet.NodeLink{}, err
	}
	if entry.ControlAddr == "" {
		return fleet.NodeLink{}, fmt.Errorf("cascade: entry node %s has no control address", entryID)
	}
	if entry.WGPublicKey == "" || exit.WGPublicKey == "" {
		return fleet.NodeLink{}, fmt.Errorf("cascade: both nodes need a configured AmneziaWG identity — run `cox nodes status` first")
	}
	if len(exit.EndpointAddrs()) == 0 {
		return fleet.NodeLink{}, fmt.Errorf("cascade: exit node %s has no public endpoint", exitID)
	}
	if innerLinkMTU < mtuFloor {
		return fleet.NodeLink{}, ErrMTUTooLow
	}

	psk, err := generatePSK()
	if err != nil {
		return fleet.NodeLink{}, err
	}
	link, err := fleet.CreateNodeLink(ctx, c.db, entryID, exitID, psk)
	if err != nil {
		return fleet.NodeLink{}, err
	}
	if err := c.configureEntryLink(ctx, entry, exit, link); err != nil {
		_ = fleet.DeleteNodeLink(ctx, c.db, link.ID) // best-effort rollback
		return fleet.NodeLink{}, err
	}
	if err := fleet.SetNodeLinkStatus(ctx, c.db, link.ID, "active", link.Version); err == nil {
		link.Status = "active"
	}
	return link, nil
}

// DeprovisionLink tears an edge down: it clears any device bindings on the link,
// reconciles the entry's transits, removes the inner interface on the entry and
// the entry peer on the exit, and deletes the row.
func (c *Coordinator) DeprovisionLink(ctx context.Context, linkID string) error {
	link, err := fleet.GetNodeLink(ctx, c.db, linkID)
	if errors.Is(err, fleet.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	devices, err := fleet.ListDeviceIDsByLink(ctx, c.db, link.ID)
	if err != nil {
		return err
	}
	for _, d := range devices {
		if err := fleet.DeleteDeviceExit(ctx, c.db, d); err != nil {
			return err
		}
	}
	entry, exit, err := c.edgeNodes(ctx, link.EntryNodeID, link.ExitNodeID)
	if err != nil {
		return err
	}
	// Remove the inner interface on the entry and the entry peer on the exit.
	if err := c.withNode(ctx, entry.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		_, err := cl.RemoveInnerLink(cctx, link.InnerInterface)
		return err
	}); err != nil {
		return err
	}
	if err := c.withNode(ctx, exit.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		_, err := cl.RemovePeer(cctx, nodev1.Protocol_PROTOCOL_AMNEZIAWG, entry.WGPublicKey)
		return err
	}); err != nil {
		return err
	}
	if err := c.pushEntryTransits(ctx, entry); err != nil {
		return err
	}
	return fleet.DeleteNodeLink(ctx, c.db, link.ID)
}

// BindExit routes a device's traffic, arriving at entry, to egress via exit over
// their inner link (which must already exist). It is also the live exit-switch:
// re-binding to a different exit replaces the binding and reconciles both the
// old and new links. The device must already have a tunnel (peer) on the entry.
func (c *Coordinator) BindExit(ctx context.Context, deviceID, entryID, exitID string) error {
	link, err := fleet.GetNodeLinkByEdge(ctx, c.db, entryID, exitID)
	if errors.Is(err, fleet.ErrNotFound) {
		return fmt.Errorf("cascade: no inner link from %s to %s — create it with `cox links add` first", entryID, exitID)
	}
	if err != nil {
		return err
	}
	if _, err := c.deviceIPOnNode(ctx, deviceID, entryID); err != nil {
		return err
	}
	if innerLinkMTU < mtuFloor {
		return ErrMTUTooLow
	}

	affected := map[string]bool{link.ID: true}
	if old, err := fleet.GetDeviceExit(ctx, c.db, deviceID); err == nil && old.NodeLinkID != link.ID {
		affected[old.NodeLinkID] = true
	} else if err != nil && !errors.Is(err, fleet.ErrNotFound) {
		return err
	}
	if err := fleet.SetDeviceExit(ctx, c.db, deviceID, link.ID); err != nil {
		return err
	}
	return c.reconcileLinks(ctx, affected)
}

// ClearExit removes a device's cascade binding (back to normal egress at its
// entry) and reconciles the link it left.
func (c *Coordinator) ClearExit(ctx context.Context, deviceID string) error {
	old, err := fleet.GetDeviceExit(ctx, c.db, deviceID)
	if errors.Is(err, fleet.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := fleet.DeleteDeviceExit(ctx, c.db, deviceID); err != nil {
		return err
	}
	return c.reconcileLinks(ctx, map[string]bool{old.NodeLinkID: true})
}

// --- internals --------------------------------------------------------------

// reconcileLinks pushes the current exit-peer membership for each affected link
// and the current transit set for each affected entry node.
func (c *Coordinator) reconcileLinks(ctx context.Context, linkIDs map[string]bool) error {
	entries := map[string]bool{}
	for lid := range linkIDs {
		link, err := fleet.GetNodeLink(ctx, c.db, lid)
		if errors.Is(err, fleet.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		entry, exit, err := c.edgeNodes(ctx, link.EntryNodeID, link.ExitNodeID)
		if err != nil {
			return err
		}
		if err := c.pushExitPeer(ctx, entry, exit, link); err != nil {
			return err
		}
		entries[entry.ID] = true
	}
	for eid := range entries {
		entry, err := fleet.GetNode(ctx, c.db, eid)
		if err != nil {
			return err
		}
		if err := c.pushEntryTransits(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

// configureEntryLink calls ConfigureInnerLink on the entry node.
func (c *Coordinator) configureEntryLink(ctx context.Context, entry, exit fleet.Node, link fleet.NodeLink) error {
	rev, err := fleet.NextNodeLinkConfigRevision(ctx, c.db, link.ID)
	if err != nil {
		return err
	}
	cfg := &nodev1.InnerLinkConfig{
		Interface:       link.InnerInterface,
		ListenPort:      uint32(link.ListenPort),
		Mtu:             innerLinkMTU,
		PeerObfuscation: control.AmneziaWGToProto(exit.Obfuscation),
		Exit: &nodev1.Peer{
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    exit.WGPublicKey,
			Endpoints:    endpointsWithPort(exit.EndpointAddrs(), awgClientPort),
			AllowedIps:   []string{"0.0.0.0/0"},
			PresharedKey: link.PresharedKey,
		},
	}
	return c.withNode(ctx, entry.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		_, err := cl.ConfigureInnerLink(cctx, cfg, rev)
		return err
	})
}

// pushExitPeer sets the exit's entry-peer AllowedIPs to exactly the tunnel
// addresses of the devices currently bound to this link. With none bound, the
// entry peer is removed from the exit.
func (c *Coordinator) pushExitPeer(ctx context.Context, entry, exit fleet.Node, link fleet.NodeLink) error {
	devices, err := fleet.ListDeviceIDsByLink(ctx, c.db, link.ID)
	if err != nil {
		return err
	}
	allowed := make([]string, 0, len(devices))
	for _, d := range devices {
		ip, err := c.deviceIPOnNode(ctx, d, entry.ID)
		if err != nil {
			return err
		}
		allowed = append(allowed, cidr32(ip))
	}
	return c.withNode(ctx, exit.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		if len(allowed) == 0 {
			_, err := cl.RemovePeer(cctx, nodev1.Protocol_PROTOCOL_AMNEZIAWG, entry.WGPublicKey)
			return err
		}
		_, err := cl.AddPeer(cctx, &nodev1.Peer{
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    entry.WGPublicKey,
			AllowedIps:   allowed,
			PresharedKey: link.PresharedKey,
		})
		return err
	})
}

// pushEntryTransits recomputes and pushes the entry node's full transit set —
// one route per device bound to any link leaving this entry — alongside its
// base forwarding/masquerade/isolation policy. Forwarding is forced on when any
// transit exists, since transit requires it.
func (c *Coordinator) pushEntryTransits(ctx context.Context, entry fleet.Node) error {
	links, err := fleet.ListNodeLinksByEntry(ctx, c.db, entry.ID)
	if err != nil {
		return err
	}
	var transits []*nodev1.TransitRoute
	for _, link := range links {
		devices, err := fleet.ListDeviceIDsByLink(ctx, c.db, link.ID)
		if err != nil {
			return err
		}
		for _, d := range devices {
			ip, err := c.deviceIPOnNode(ctx, d, entry.ID)
			if err != nil {
				return err
			}
			transits = append(transits, &nodev1.TransitRoute{
				DeviceCidr:     cidr32(ip),
				InnerInterface: link.InnerInterface,
				Mark:           uint32(link.Fwmark),
				Table:          uint32(link.TableID),
			})
		}
	}
	forwarding := entry.Forwarding || len(transits) > 0
	return c.withNode(ctx, entry.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		_, err := cl.SetNetworkConfig(cctx, forwarding, entry.Masquerade, entry.Isolation, transits)
		return err
	})
}

// edgeNodes fetches an edge's entry and exit nodes.
func (c *Coordinator) edgeNodes(ctx context.Context, entryID, exitID string) (entry, exit fleet.Node, err error) {
	if entry, err = fleet.GetNode(ctx, c.db, entryID); err != nil {
		return fleet.Node{}, fleet.Node{}, fmt.Errorf("cascade: entry node: %w", err)
	}
	if exit, err = fleet.GetNode(ctx, c.db, exitID); err != nil {
		return fleet.Node{}, fleet.Node{}, fmt.Errorf("cascade: exit node: %w", err)
	}
	return entry, exit, nil
}

// deviceIPOnNode returns the device's tunnel address on a node, or an error if
// the device has no peer there.
func (c *Coordinator) deviceIPOnNode(ctx context.Context, deviceID, nodeID string) (string, error) {
	peers, err := fleet.ListPeersByDevice(ctx, c.db, deviceID)
	if err != nil {
		return "", err
	}
	for _, p := range peers {
		if p.NodeID == nodeID && p.AllowedIP != "" {
			return p.AllowedIP, nil
		}
	}
	return "", fmt.Errorf("cascade: device %s has no tunnel on entry node %s", deviceID, nodeID)
}

// withNode dials a node, runs fn with a bounded context, and closes the client.
func (c *Coordinator) withNode(ctx context.Context, addr string, fn func(NodeClient, context.Context) error) error {
	if addr == "" {
		return fmt.Errorf("cascade: node has no control address")
	}
	cl, err := c.dial(addr)
	if err != nil {
		return fmt.Errorf("cascade: dial %s: %w", addr, err)
	}
	defer cl.Close()
	cctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	return fn(cl, cctx)
}

// generatePSK returns a fresh 32-byte WireGuard preshared key, base64-encoded.
func generatePSK() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cascade: generate PSK: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// endpointsWithPort appends :port to each address that lacks one.
func endpointsWithPort(addrs []string, port int) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if strings.Contains(a, ":") && !strings.Contains(a, "]") {
			// already host:port (and not a bare IPv6); leave it.
			out = append(out, a)
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", a, port))
	}
	return out
}

// cidr32 returns ip as a /32 host route if it carries no mask.
func cidr32(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/32"
}
