// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"fmt"

	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"github.com/PharosVPN/coxswain/internal/wg"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// Client is coxswain's control connection to one buoy node. It is safe for
// concurrent use; close it when done.
type Client struct {
	cc  *grpc.ClientConn
	rpc buoyv1.NodeControlClient
}

// Close releases the connection.
func (c *Client) Close() error { return c.cc.Close() }

// NewClientFromConn wraps an existing *grpc.ClientConn in a control Client.
// Dialer.Dial is the production path; this exists for tests that need to drive
// the Client over an in-memory transport.
func NewClientFromConn(cc *grpc.ClientConn) *Client {
	return &Client{cc: cc, rpc: buoyv1.NewNodeControlClient(cc)}
}

// Status reports node and per-protocol service health.
func (c *Client) Status(ctx context.Context) (*buoyv1.GetStatusResponse, error) {
	return c.rpc.GetStatus(ctx, &buoyv1.GetStatusRequest{})
}

// AmneziaWGFromStatus extracts the AmneziaWG server identity a node reported
// in a GetStatus response — its public key and obfuscation parameter set. It
// returns zero values when the node has not yet configured its data plane.
func AmneziaWGFromStatus(s *buoyv1.GetStatusResponse) (publicKey string, obf wg.Obfuscation) {
	info := s.GetAmneziawg()
	if info == nil {
		return "", wg.Obfuscation{}
	}
	o := info.GetObfuscation()
	if o == nil {
		return info.GetPublicKey(), wg.Obfuscation{}
	}
	return info.GetPublicKey(), wg.Obfuscation{
		Jc: o.GetJc(), Jmin: o.GetJmin(), Jmax: o.GetJmax(),
		S1: o.GetS1(), S2: o.GetS2(), S3: o.GetS3(), S4: o.GetS4(),
		H1: o.GetH1(), H2: o.GetH2(), H3: o.GetH3(), H4: o.GetH4(),
		I1: o.GetI1(), I2: o.GetI2(), I3: o.GetI3(), I4: o.GetI4(), I5: o.GetI5(),
	}
}

// AmneziaWGToProto is the inverse of AmneziaWGFromStatus: it renders a node's
// obfuscation set to its wire form. A cascade inner link carries the exit
// node's set so the entry's handshake to the exit matches (DESIGN §3).
func AmneziaWGToProto(o wg.Obfuscation) *buoyv1.AmneziaWGObfuscation {
	return &buoyv1.AmneziaWGObfuscation{
		Jc: o.Jc, Jmin: o.Jmin, Jmax: o.Jmax,
		S1: o.S1, S2: o.S2, S3: o.S3, S4: o.S4,
		H1: o.H1, H2: o.H2, H3: o.H3, H4: o.H4,
		I1: o.I1, I2: o.I2, I3: o.I3, I4: o.I4, I5: o.I5,
	}
}

// Metrics reports the node's counters for a metrics sample.
func (c *Client) Metrics(ctx context.Context) (*buoyv1.GetMetricsResponse, error) {
	return c.rpc.GetMetrics(ctx, &buoyv1.GetMetricsRequest{})
}

// PushAmneziaWGConfig encodes a full AmneziaWG peer set and replaces the
// node's data-plane config in one call. coxswain sends peers only — node-level
// obfuscation is buoy's domain (decision-14 follow-up) and stays out of the
// payload.
func (c *Client) PushAmneziaWGConfig(ctx context.Context, revision int64, peers []*buoyv1.Peer) (*buoyv1.PushConfigResponse, error) {
	cfg, err := proto.Marshal(&buoyv1.AmneziaWGConfig{Peers: peers})
	if err != nil {
		return nil, fmt.Errorf("control: marshal amneziawg config: %w", err)
	}
	return c.PushConfig(ctx, buoyv1.Protocol_PROTOCOL_AMNEZIAWG, revision, cfg)
}

// PushConfig replaces the data-plane config for one protocol. Callers usually
// want PushAmneziaWGConfig (or the future XRay equivalent), which handles the
// encoding — this is the raw path for forwarders and tests.
func (c *Client) PushConfig(ctx context.Context, protocol buoyv1.Protocol, revision int64, config []byte) (*buoyv1.PushConfigResponse, error) {
	return c.rpc.PushConfig(ctx, &buoyv1.PushConfigRequest{
		Protocol: protocol,
		Revision: revision,
		Config:   config,
	})
}

// AddPeer adds a single peer live.
func (c *Client) AddPeer(ctx context.Context, peer *buoyv1.Peer) (*buoyv1.PeerResponse, error) {
	return c.rpc.AddPeer(ctx, &buoyv1.AddPeerRequest{Peer: peer})
}

// RemovePeer revokes a single peer live.
func (c *Client) RemovePeer(ctx context.Context, protocol buoyv1.Protocol, publicKey string) (*buoyv1.PeerResponse, error) {
	return c.rpc.RemovePeer(ctx, &buoyv1.RemovePeerRequest{
		Protocol:  protocol,
		PublicKey: publicKey,
	})
}

// ListPeers returns configured peers and their runtime state. A protocol of
// PROTOCOL_UNSPECIFIED returns every peer.
func (c *Client) ListPeers(ctx context.Context, protocol buoyv1.Protocol) (*buoyv1.ListPeersResponse, error) {
	return c.rpc.ListPeers(ctx, &buoyv1.ListPeersRequest{Protocol: protocol})
}

// RestartService restarts one protocol's data-plane service on the node.
func (c *Client) RestartService(ctx context.Context, protocol buoyv1.Protocol) (*buoyv1.RestartServiceResponse, error) {
	return c.rpc.RestartService(ctx, &buoyv1.RestartServiceRequest{Protocol: protocol})
}

// WatchEvents opens the node's live event server-stream. The caller reads
// events with Recv until ctx is cancelled or the stream ends.
func (c *Client) WatchEvents(ctx context.Context) (grpc.ServerStreamingClient[buoyv1.Event], error) {
	return c.rpc.WatchEvents(ctx, &buoyv1.WatchEventsRequest{})
}

// SetNetworkConfig applies the node's forwarding / masquerade / isolation
// policy (DESIGN §3, decision 16).
func (c *Client) SetNetworkConfig(ctx context.Context, forwarding, masquerade, isolation bool, transits []*buoyv1.TransitRoute) (*buoyv1.SetNetworkConfigResponse, error) {
	return c.rpc.SetNetworkConfig(ctx, &buoyv1.SetNetworkConfigRequest{
		Config: &buoyv1.NetworkConfig{
			Forwarding: forwarding,
			Masquerade: masquerade,
			Isolation:  isolation,
			Transits:   transits,
		},
	})
}

// ConfigureInnerLink creates or updates a node→node inner AmneziaWG link on an
// entry node toward an exit (DESIGN §3, node cascade). revision is the link's
// monotonic ConfigureInnerLink revision.
func (c *Client) ConfigureInnerLink(ctx context.Context, cfg *buoyv1.InnerLinkConfig, revision int64) (*buoyv1.ConfigureInnerLinkResponse, error) {
	return c.rpc.ConfigureInnerLink(ctx, &buoyv1.ConfigureInnerLinkRequest{
		Config:   cfg,
		Revision: revision,
	})
}

// RemoveInnerLink tears down an inner link on an entry node.
func (c *Client) RemoveInnerLink(ctx context.Context, iface string) (*buoyv1.RemoveInnerLinkResponse, error) {
	return c.rpc.RemoveInnerLink(ctx, &buoyv1.RemoveInnerLinkRequest{Interface: iface})
}
