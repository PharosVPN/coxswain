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
//
// When the stream drops (node restart, network blip, ctx cancel), any peers
// that connected over this stream but never disconnected would otherwise dangle
// as open sessions forever — the node emits no disconnect on a crash, and on
// reconnect it re-reports current peers as fresh connects. So before returning
// we close out those open sessions with a synthetic, attributed disconnect, so
// the persisted history does not leave a session open indefinitely.
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

	// Peers seen connect (and not yet disconnect) over THIS stream, keyed by
	// peer public key, carrying the last enriched event so the synthetic
	// disconnect keeps the device/user/source attribution.
	open := map[string]Event{}
	defer closeOpenSessions(open, hub, sink)

	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		enriched := ingest(ctx, node.ID, ev, sink)
		switch ev.GetType() {
		case nodev1.EventType_EVENT_TYPE_PEER_CONNECTED:
			if enriched.PeerID != "" {
				open[enriched.PeerID] = enriched
			}
		case nodev1.EventType_EVENT_TYPE_PEER_DISCONNECTED:
			delete(open, enriched.PeerID)
		}
		hub.Publish(enriched)
	}
}

// closeOpenSessions closes out every peer left open when a node's stream drops,
// so a lost stream / node restart does not dangle sessions forever. For each open
// peer it (1) persists a synthetic disconnect to the history sink and (2)
// publishes a matching PEER_DISCONNECTED to the live hub, so the SSE/WS dashboard
// feed and the gRPC SIEM stream also see the session close — otherwise those
// feeds would show the session open indefinitely. Both carry reason "stream-lost"
// and the full device/user/source attribution, so a synthetic close-out is
// distinguishable from a node-reported disconnect. It is best-effort and
// idempotent: the node re-reports live peers as fresh connects on reconnect, and
// a real disconnect that arrived first already removed the peer from `open`. A
// nil sink skips persistence; the hub publish still happens (the live tests pass
// a nil sink). A nil hub skips the publish.
func closeOpenSessions(open map[string]Event, hub *Hub, sink Sink) {
	if len(open) == 0 {
		return
	}
	at := time.Now().UTC()
	for _, ev := range open {
		// Synthetic disconnect: keep the original event's attribution, stamp it
		// "now", and mark it stream-lost.
		ev.Type = "PEER_DISCONNECTED"
		ev.At = at
		ev.Message = ""
		ev.Reason = "stream-lost"

		if hub != nil {
			hub.Publish(ev)
		}
		if sink != nil {
			rec := record(ev, "disconnect")
			rec.Reason = "stream-lost"
			sink.Ingest(rec)
			if fr, ok := sink.(interface{ Forget(string) }); ok && ev.PeerID != "" {
				fr.Forget(ev.PeerID)
			}
		}
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
