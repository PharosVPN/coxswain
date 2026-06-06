// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package cascade coordinates the node-cascade data plane (DESIGN §3, decision
// 18): named multi-hop paths entry → [mid] → exit. coxswain is the sole mesh
// coordinator. It provisions the inner AmneziaWG links between consecutive hops
// and binds a device's traffic to a path, driving every node over the control
// plane.
//
// An inner link terminates on the next hop's client interface (awg0): the
// dialing node runs ConfigureInnerLink toward the target's public endpoint, and
// the target sees the dialer as an ordinary forwarded peer whose AllowedIPs
// accumulate the cascaded devices' tunnel addresses. A node policy-routes a
// cascaded device into the inner link toward the next hop (a transit, no SNAT);
// the final hop (exit) masquerades. A *mid* is simply a node with both — it
// receives the previous hop as a peer AND dials the next hop with a transit —
// so it composes from the same primitives, no new node capability.
//
// The one invariant that makes multi-hop correct: at *every* hop the device's
// tunnel CIDR is the address allocated on the PATH ENTRY (hops[0]), since a
// client only ever handshakes with, and holds credentials for, its entry.
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
	// each hop dials the next hop there for the inner link (DESIGN §3).
	awgClientPort = 443
	// innerLinkMTU is every inner interface's MTU: the client MTU (1420) less one
	// AmneziaWG encapsulation. It is constant at every hop — each node fully
	// decapsulates and re-encapsulates, so there is one AmneziaWG layer per
	// physical link, never nested, and a 2-hop path stays above the IPv6 floor.
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

// ProvisionPath brings up the inner-link chain for a path: an inner AmneziaWG
// interface on each hop dialing the next. The per-device peers and transit
// routes are wired when a device binds (BindDeviceToPath), so a freshly
// provisioned path carries no traffic until then. Idempotent — re-running heals
// drift (ConfigureInnerLink is create-or-update). The edge (node_link) for each
// segment is shared across paths that traverse the same pair.
func (c *Coordinator) ProvisionPath(ctx context.Context, pathID string) (fleet.Path, error) {
	p, err := fleet.GetPath(ctx, c.db, pathID)
	if err != nil {
		return fleet.Path{}, err
	}
	hops, err := fleet.ListPathHops(ctx, c.db, pathID)
	if err != nil {
		return fleet.Path{}, err
	}
	if len(hops) < 2 {
		return fleet.Path{}, fmt.Errorf("cascade: path %s has fewer than two hops", pathID)
	}
	if len(hops)-1 > fleet.MaxPathHops {
		return fleet.Path{}, fmt.Errorf("cascade: path %s exceeds the %d-hop limit", pathID, fleet.MaxPathHops)
	}
	if innerLinkMTU < mtuFloor {
		return fleet.Path{}, ErrMTUTooLow
	}

	nodes := make([]fleet.Node, len(hops))
	for i, h := range hops {
		n, err := fleet.GetNode(ctx, c.db, h.NodeID)
		if err != nil {
			return fleet.Path{}, fmt.Errorf("cascade: path hop %d: %w", i, err)
		}
		nodes[i] = n
	}

	for i := 0; i < len(nodes)-1; i++ {
		entry, exit := nodes[i], nodes[i+1]
		if err := validateSegment(entry, exit); err != nil {
			_ = fleet.SetPathStatus(ctx, c.db, pathID, "error", p.Version)
			return fleet.Path{}, err
		}
		if _, err := c.ensureEdge(ctx, entry, exit); err != nil {
			_ = fleet.SetPathStatus(ctx, c.db, pathID, "error", p.Version)
			return fleet.Path{}, err
		}
	}
	if err := fleet.SetPathStatus(ctx, c.db, pathID, fleet.StatusActive, p.Version); err == nil {
		p.Status = fleet.StatusActive
	}
	return p, nil
}

// DeprovisionPath tears a path down: it unbinds every device on the path,
// reconciles so any sibling path sharing an edge keeps its state, removes each
// segment's inner interface (only when no other path still uses that edge), and
// deletes the path row (its hops cascade).
func (c *Coordinator) DeprovisionPath(ctx context.Context, pathID string) error {
	if _, err := fleet.GetPath(ctx, c.db, pathID); errors.Is(err, fleet.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	hops, err := fleet.ListPathHops(ctx, c.db, pathID)
	if err != nil {
		return err
	}

	// 1. Unbind every device on this path.
	devices, err := fleet.ListDeviceIDsByPath(ctx, c.db, pathID)
	if err != nil {
		return err
	}
	for _, d := range devices {
		if err := fleet.DeleteDeviceExit(ctx, c.db, d); err != nil {
			return err
		}
	}

	// 2. Reconcile this path plus any sibling sharing one of its edges, so a
	//    shared edge re-converges to the surviving paths' device union before we
	//    consider tearing anything down.
	affected := map[string]bool{pathID: true}
	for i := 0; i < len(hops)-1; i++ {
		siblings, err := fleet.ListPathsByEdge(ctx, c.db, hops[i].NodeID, hops[i+1].NodeID)
		if err != nil {
			return err
		}
		for _, s := range siblings {
			affected[s] = true
		}
	}
	if err := c.reconcile(ctx, affected); err != nil {
		return err
	}

	// 3. Remove each segment's inner interface, but only if this is the last path
	//    using that edge (the ref-count includes the path being torn down, so
	//    <= 1 means "only this one"). Skipping a shared edge keeps siblings alive.
	for i := 0; i < len(hops)-1; i++ {
		entry, exit, err := c.edgeNodes(ctx, hops[i].NodeID, hops[i+1].NodeID)
		if err != nil {
			return err
		}
		link, err := fleet.GetNodeLinkByEdge(ctx, c.db, entry.ID, exit.ID)
		if errors.Is(err, fleet.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		cnt, err := fleet.CountPathsUsingLink(ctx, c.db, link.ID)
		if err != nil {
			return err
		}
		if cnt > 1 {
			continue
		}
		if err := c.withNode(ctx, entry.ControlAddr, func(cl NodeClient, cctx context.Context) error {
			_, err := cl.RemoveInnerLink(cctx, link.InnerInterface)
			return err
		}); err != nil {
			return err
		}
		// Belt and braces: reconcile already cleared the exit peer when no device
		// remained, but drop it explicitly in case the edge had none bound.
		_ = c.withNode(ctx, exit.ControlAddr, func(cl NodeClient, cctx context.Context) error {
			_, err := cl.RemovePeer(cctx, nodev1.Protocol_PROTOCOL_AMNEZIAWG, entry.WGPublicKey)
			return err
		})
		if err := fleet.DeleteNodeLink(ctx, c.db, link.ID); err != nil {
			return err
		}
	}

	return fleet.DeletePath(ctx, c.db, pathID)
}

// BindDeviceToPath routes a device's traffic, arriving at the path entry, along
// the path to egress at its exit. The path must already be provisioned and the
// device must already have a tunnel (peer) on the path entry. It is also the
// live switch: re-binding to a different path replaces the binding and
// reconciles both the old and new paths.
func (c *Coordinator) BindDeviceToPath(ctx context.Context, deviceID, pathID string) error {
	hops, err := fleet.ListPathHops(ctx, c.db, pathID)
	if err != nil {
		return err
	}
	if len(hops) < 2 {
		return fmt.Errorf("cascade: path %s has fewer than two hops", pathID)
	}
	if _, err := c.deviceIPOnNode(ctx, deviceID, hops[0].NodeID); err != nil {
		return err
	}
	if innerLinkMTU < mtuFloor {
		return ErrMTUTooLow
	}

	affected := map[string]bool{pathID: true}
	if old, err := fleet.GetDeviceExit(ctx, c.db, deviceID); err == nil && old.PathID != pathID {
		affected[old.PathID] = true
	} else if err != nil && !errors.Is(err, fleet.ErrNotFound) {
		return err
	}
	if err := fleet.SetDeviceExit(ctx, c.db, deviceID, pathID); err != nil {
		return err
	}
	return c.reconcile(ctx, affected)
}

// ClearDevicePath removes a device's path binding (back to normal egress at its
// entry) and reconciles the path it left.
func (c *Coordinator) ClearDevicePath(ctx context.Context, deviceID string) error {
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
	return c.reconcile(ctx, map[string]bool{old.PathID: true})
}

// ReconcileNode re-applies the cascade edge peers and transit routes for every
// path that traverses nodeID. A device-peer PushConfig (`cox nodes push`)
// full-replaces a node's awg0 peers, which wipes the coordinator-managed edge
// peer on an exit/mid hop — the previous hop's key carrying the cascaded devices'
// allowed-IPs. Call this right after such a push so the edge peer is re-added
// last and re-owns those allowed-IPs (AddPeer moves an allowed-IP to whichever
// peer claims it last). No-op when the node is in no path.
func (c *Coordinator) ReconcileNode(ctx context.Context, nodeID string) error {
	pids, err := fleet.ListPathIDsContainingNode(ctx, c.db, nodeID)
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return nil
	}
	set := make(map[string]bool, len(pids))
	for _, p := range pids {
		set[p] = true
	}
	return c.reconcile(ctx, set)
}

// --- internals --------------------------------------------------------------

// reconcile recomputes the desired data-plane state for every edge and transit-
// owning node touched by the affected paths, and pushes it. Desired state is a
// pure function of (paths, hops, device bindings, node tunnel IPs); both the
// edge-peer membership and the per-node transit set are unioned across all
// paths, so reconciling one path naturally keeps a shared edge's siblings
// intact. Exit peers are pushed before transits so a freshly marked packet
// never points at a downstream hop that hasn't accepted the device yet.
func (c *Coordinator) reconcile(ctx context.Context, pathIDs map[string]bool) error {
	type edge struct{ entry, exit string }
	edges := map[edge]bool{}
	transitNodes := map[string]bool{}
	for pid := range pathIDs {
		hops, err := fleet.ListPathHops(ctx, c.db, pid)
		if err != nil {
			return err
		}
		for i := 0; i < len(hops)-1; i++ {
			edges[edge{hops[i].NodeID, hops[i+1].NodeID}] = true
			transitNodes[hops[i].NodeID] = true
		}
	}
	for e := range edges {
		if err := c.pushEdgePeer(ctx, e.entry, e.exit); err != nil {
			return err
		}
	}
	for nid := range transitNodes {
		node, err := fleet.GetNode(ctx, c.db, nid)
		if err != nil {
			return err
		}
		if err := c.pushNodeTransits(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

// ensureEdge returns the node_link for the entry→exit segment, creating it (and
// allocating the entry-side inner-link resources) if absent, then runs
// ConfigureInnerLink on the entry. The row is shared across paths that traverse
// the same pair. Idempotent.
func (c *Coordinator) ensureEdge(ctx context.Context, entry, exit fleet.Node) (fleet.NodeLink, error) {
	link, err := fleet.GetNodeLinkByEdge(ctx, c.db, entry.ID, exit.ID)
	if errors.Is(err, fleet.ErrNotFound) {
		psk, gErr := generatePSK()
		if gErr != nil {
			return fleet.NodeLink{}, gErr
		}
		link, err = fleet.CreateNodeLink(ctx, c.db, entry.ID, exit.ID, psk)
	}
	if err != nil {
		return fleet.NodeLink{}, err
	}
	if err := c.configureEntryLink(ctx, entry, exit, link); err != nil {
		return fleet.NodeLink{}, err
	}
	if link.Status != fleet.StatusActive {
		if sErr := fleet.SetNodeLinkStatus(ctx, c.db, link.ID, fleet.StatusActive, link.Version); sErr == nil {
			link.Status = fleet.StatusActive
		}
	}
	return link, nil
}

// configureEntryLink calls ConfigureInnerLink on the entry node so it dials the
// exit (segment target) over the inner link, carrying the exit's obfuscation.
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

// pushEdgePeer sets the exit's peer (the segment entry) AllowedIPs to exactly
// the path-entry tunnel addresses of every device on any path traversing this
// edge. With none, the peer is removed from the exit.
func (c *Coordinator) pushEdgePeer(ctx context.Context, entryID, exitID string) error {
	entry, exit, err := c.edgeNodes(ctx, entryID, exitID)
	if err != nil {
		return err
	}
	link, err := fleet.GetNodeLinkByEdge(ctx, c.db, entryID, exitID)
	if err != nil {
		return err
	}
	allowed, err := c.devicesOnEdge(ctx, entryID, exitID)
	if err != nil {
		return err
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

// pushNodeTransits recomputes and pushes a node's full transit set — one route
// per cascaded source, for every downstream hop the node has across all paths —
// alongside its base forwarding/masquerade/isolation policy. The source CIDR is
// always the address on the PATH ENTRY. Forwarding is forced on when any transit
// exists, since transit requires it.
func (c *Coordinator) pushNodeTransits(ctx context.Context, node fleet.Node) error {
	pids, err := fleet.ListPathIDsContainingNode(ctx, c.db, node.ID)
	if err != nil {
		return err
	}
	var transits []*nodev1.TransitRoute
	seen := map[string]bool{}
	for _, pid := range pids {
		hops, err := fleet.ListPathHops(ctx, c.db, pid)
		if err != nil {
			return err
		}
		idx := indexOfNode(hops, node.ID)
		if idx < 0 || idx >= len(hops)-1 {
			continue // not present, or the exit (no downstream hop)
		}
		link, err := fleet.GetNodeLinkByEdge(ctx, c.db, node.ID, hops[idx+1].NodeID)
		if errors.Is(err, fleet.ErrNotFound) {
			continue // segment not provisioned yet
		}
		if err != nil {
			return err
		}
		cidrs, err := c.pathEntryCIDRs(ctx, pid, hops)
		if err != nil {
			return err
		}
		for _, cidr := range cidrs {
			key := cidr + "@" + link.InnerInterface
			if seen[key] {
				continue
			}
			seen[key] = true
			transits = append(transits, &nodev1.TransitRoute{
				DeviceCidr:     cidr,
				InnerInterface: link.InnerInterface,
				Mark:           uint32(link.Fwmark),
				Table:          uint32(link.TableID),
			})
		}
	}
	forwarding := node.Forwarding || len(transits) > 0
	return c.withNode(ctx, node.ControlAddr, func(cl NodeClient, cctx context.Context) error {
		_, err := cl.SetNetworkConfig(cctx, forwarding, node.Masquerade, node.Isolation, transits)
		return err
	})
}

// devicesOnEdge returns the deduplicated path-entry tunnel CIDRs of every
// cascaded source on any path that traverses the entry→exit edge as a
// consecutive hop pair.
func (c *Coordinator) devicesOnEdge(ctx context.Context, entryID, exitID string) ([]string, error) {
	pids, err := fleet.ListPathsByEdge(ctx, c.db, entryID, exitID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, pid := range pids {
		hops, err := fleet.ListPathHops(ctx, c.db, pid)
		if err != nil {
			return nil, err
		}
		if len(hops) == 0 {
			continue
		}
		cidrs, err := c.pathEntryCIDRs(ctx, pid, hops)
		if err != nil {
			return nil, err
		}
		for _, cidr := range cidrs {
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out, nil
}

// pathEntryCIDRs returns the deduplicated path-entry tunnel CIDRs of every source
// routed through a path: the legacy device_exits bindings (auto-profile devices)
// and the per-profile bindings (profile_specs whose path_id is this path). Each
// source's CIDR is its address on the PATH ENTRY (hops[0]) — the one invariant
// that makes multi-hop correct, since a client only ever holds credentials for
// its entry.
func (c *Coordinator) pathEntryCIDRs(ctx context.Context, pid string, hops []fleet.PathHop) ([]string, error) {
	if len(hops) == 0 {
		return nil, nil
	}
	entryNode := hops[0].NodeID
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		cidr := cidr32(ip)
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}

	devices, err := fleet.ListDeviceIDsByPath(ctx, c.db, pid)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		ip, err := c.deviceIPOnNode(ctx, d, entryNode)
		if err != nil {
			return nil, err
		}
		add(ip)
	}

	specs, err := fleet.ListProfileSpecsByPath(ctx, c.db, pid)
	if err != nil {
		return nil, err
	}
	for _, s := range specs {
		ip, err := c.specIPOnNode(ctx, s, entryNode)
		if err != nil {
			return nil, err
		}
		add(ip)
	}
	return out, nil
}

// specIPOnNode returns a profile's tunnel address on a node — the AllowedIP of
// the peer tagged with the spec id — or an error if the profile has no peer
// there (not yet provisioned).
func (c *Coordinator) specIPOnNode(ctx context.Context, spec fleet.ProfileSpec, nodeID string) (string, error) {
	peers, err := fleet.ListPeersByDevice(ctx, c.db, spec.DeviceID)
	if err != nil {
		return "", err
	}
	for _, p := range peers {
		if p.NodeID == nodeID && p.ProfileSpecID == spec.ID && p.AllowedIP != "" {
			return p.AllowedIP, nil
		}
	}
	return "", fmt.Errorf("cascade: profile %s has no tunnel on path entry node %s", spec.ID, nodeID)
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
	return "", fmt.Errorf("cascade: device %s has no tunnel on path entry node %s", deviceID, nodeID)
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

// validateSegment checks a segment's endpoints can carry an inner link: the
// entry must be controllable, both nodes need an AmneziaWG identity, and the
// exit must be publicly reachable for the entry to dial.
func validateSegment(entry, exit fleet.Node) error {
	if entry.ControlAddr == "" {
		return fmt.Errorf("cascade: node %s has no control address", entry.ID)
	}
	if entry.WGPublicKey == "" || exit.WGPublicKey == "" {
		return fmt.Errorf("cascade: both nodes need a configured AmneziaWG identity — run `cox nodes status` first")
	}
	if len(exit.EndpointAddrs()) == 0 {
		return fmt.Errorf("cascade: node %s has no public endpoint", exit.ID)
	}
	return nil
}

// indexOfNode returns the hop index of nodeID in hops, or -1.
func indexOfNode(hops []fleet.PathHop, nodeID string) int {
	for i, h := range hops {
		if h.NodeID == nodeID {
			return i
		}
	}
	return -1
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
