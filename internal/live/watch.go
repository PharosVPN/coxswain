// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package live

import (
	"context"
	"log/slog"
	"time"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/fleet"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/monitor"
)

const (
	watchBackoffMin = 2 * time.Second
	watchBackoffMax = 60 * time.Second
)

// Sink is the connection-history ingestion surface the live plane writes to
// before fanning an event to the hub. *monitor.Store satisfies it. A nil Sink
// disables persistence (the live stream still works); the live tests pass nil.
type Sink interface {
	// Resolve maps a peer public key to its device/user (cached + best-effort).
	Resolve(ctx context.Context, peerID string) monitor.Resolution
	// Ingest persists a resolved session event. It must never block — a slow DB
	// must not stall the live stream.
	Ingest(ev monitor.Event)
}

// WatchNode holds a node's WatchEvents stream open, publishing every
// event to the hub. It reconnects with capped exponential backoff and returns
// only when ctx is cancelled — a controller staying connected through node
// restarts is the point of the live plane.
//
// sink, when non-nil, is the connection-history store: each event is resolved
// (peer → device/user) and the session boundaries are persisted to it before
// the event fans out, so the firehose becomes durable history. Resolution also
// enriches the live event so the WebSocket stream carries device + source IP.
func WatchNode(ctx context.Context, dialer *control.Dialer, node fleet.Node, hub *Hub, sink Sink) {
	backoff := watchBackoffMin
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := streamNode(ctx, dialer, node, hub, sink)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("node event stream dropped", "node", node.ID, "err", err)
		}
		// A stream that stayed up is not a flapping node — reset the backoff.
		if time.Since(start) >= watchBackoffMin {
			backoff = watchBackoffMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < watchBackoffMax {
			backoff = min(backoff*2, watchBackoffMax)
		}
	}
}

// streamNode runs one connection: dial the node, consume its event stream
// until it ends or errors. Each event is resolved + persisted (best-effort,
// non-blocking) before it fans to the hub.
func streamNode(ctx context.Context, dialer *control.Dialer, node fleet.Node, hub *Hub, sink Sink) error {
	client, err := dialer.Dial(node.ControlAddr)
	if err != nil {
		return err
	}
	defer client.Close()

	stream, err := client.WatchEvents(ctx)
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		hub.Publish(ingest(ctx, node.ID, ev, sink))
	}
}

// ingest converts a node proto event into a live.Event, enriches it with the
// resolved device/user/source IP, and persists the session boundary to the
// sink (connect / disconnect). It returns the enriched event for the hub. A nil
// sink skips resolution + persistence but still returns the base event, so the
// live stream is unaffected when history is disabled.
func ingest(ctx context.Context, nodeID string, e *nodev1.Event, sink Sink) Event {
	ev := eventFrom(nodeID, e)
	ev.SourceIP = monitor.SourceIP(ev.SourceEndpoint)
	if sink == nil {
		return ev
	}

	res := sink.Resolve(ctx, ev.PeerID)
	ev.DeviceID = res.DeviceID
	ev.User = res.UserID

	// Persist session boundaries only — connects and disconnects (a source-IP
	// change arrives from the node as a fresh PEER_CONNECTED, so it is captured
	// here too). Handshake keepalives stay ephemeral on the live stream; storing
	// every rekey would bloat the history without adding session signal.
	switch e.GetType() {
	case nodev1.EventType_EVENT_TYPE_PEER_CONNECTED:
		sink.Ingest(record(ev, "connect"))
	case nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED:
		sink.Ingest(record(ev, "disconnect"))
		// A peer gone for good should not pin a stale resolution forever.
		if fr, ok := sink.(interface{ Forget(string) }); ok && ev.PeerID != "" {
			fr.Forget(ev.PeerID)
		}
	}
	return ev
}

// record builds a monitor.Event from an enriched live event for the given
// session event type.
func record(ev Event, eventType string) monitor.Event {
	return monitor.Event{
		At:             ev.At,
		NodeID:         ev.NodeID,
		PeerID:         ev.PeerID,
		DeviceID:       ev.DeviceID,
		UserID:         ev.User,
		Protocol:       ev.Protocol,
		EventType:      eventType,
		SourceIP:       ev.SourceIP,
		SourceEndpoint: ev.SourceEndpoint,
	}
}
