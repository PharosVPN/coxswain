// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package siem is coxswain's optional inbound gRPC monitoring stream for
// SIEM/enterprise ingestion. An enterprise consumer dials IN (coxswain is the
// gRPC server here, unlike the outbound NodeControl client), authenticates with
// a monitor-scope API token, and receives a live stream of monitoring events.
//
// The event source is the existing live.Hub — the same fan-out the admin
// dashboard WebSocket consumes. There is no second event pipeline: this server
// is just another Hub subscriber that translates live.Event into the
// monitor.v1 wire shape and applies an optional per-client kinds filter.
//
// The listener is OFF by default (siem.listen unset); coxswain keeps zero
// inbound ports unless explicitly configured (DESIGN §2, §6).
package siem

import (
	"context"
	"encoding/json"
	"math"
	"sync/atomic"

	"github.com/PharosVPN/coxswain/internal/analytics"
	monitorv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/monitor/v1"
	"github.com/PharosVPN/coxswain/internal/live"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// clientBuffer is how many events a single SIEM consumer may fall behind before
// further events are DROPPED for it. A slow consumer must never stall the hub
// (and thus the fleet's live plane), so on overflow we drop and count rather
// than block. It mirrors live.subscriberBuffer's slow-subscriber posture.
const clientBuffer = 256

// Server implements monitor.v1 MonitorStream by subscribing to the live Hub.
type Server struct {
	monitorv1.UnimplementedMonitorStreamServer

	hub *live.Hub
	// onSubscribe, when non-nil, is invoked once per accepted Subscribe call
	// (after auth) with the request context — used to write the audit row. It
	// must not block; serve.go runs it inline.
	onSubscribe func(ctx context.Context)
	// dropped counts events dropped across all consumers due to a full per-client
	// buffer (backpressure). Exposed for diagnostics.
	dropped atomic.Int64
}

// NewServer returns a MonitorStream server backed by hub. onSubscribe (optional)
// is called once per accepted Subscribe to record an audit row.
func NewServer(hub *live.Hub, onSubscribe func(ctx context.Context)) *Server {
	return &Server{hub: hub, onSubscribe: onSubscribe}
}

// Dropped reports how many events have been dropped across all consumers because
// a consumer's buffer was full (backpressure / slow-consumer protection).
func (s *Server) Dropped() int64 { return s.dropped.Load() }

// Subscribe streams monitoring events to one SIEM consumer until the client
// disconnects or the server context is cancelled. It registers a Hub subscriber
// (which gives us the same enriched events the dashboard sees), translates each
// live.Event into a monitor.v1 MonitorEvent, applies the request's kinds filter,
// and sends it. The interceptor has already authenticated the caller and
// required monitor scope before we get here.
//
// Backpressure: the Hub already drops to its own per-subscriber buffer when
// THIS Subscribe loop falls behind draining `ch`. On top of that, gRPC's
// stream.Send can block on a slow network peer; if we called it inline, a stalled
// consumer would back the drain up into the hub. So we split the work: this
// goroutine drains the hub channel into a bounded local outbox, and a send
// goroutine pulls from the outbox and calls Send. When the outbox is full we DROP
// the newest event and count it — never block the drain (and thus never the hub).
func (s *Server) Subscribe(req *monitorv1.SubscribeRequest, stream monitorv1.MonitorStream_SubscribeServer) error {
	if s.onSubscribe != nil {
		s.onSubscribe(stream.Context())
	}

	want := kindSet(req.GetKinds())

	id, ch := s.hub.Subscribe()
	defer s.hub.Unsubscribe(id)

	ctx := stream.Context()

	// out carries already-translated, already-filtered events to the send
	// goroutine; sendErr reports the first Send failure so Subscribe can return it.
	out := make(chan *monitorv1.MonitorEvent, clientBuffer)
	sendErr := make(chan error, 1)
	go func() {
		for me := range out {
			if err := stream.Send(me); err != nil {
				select {
				case sendErr <- err:
				default:
				}
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			close(out)
			return ctx.Err()
		case err := <-sendErr:
			close(out)
			return err
		case ev, ok := <-ch:
			if !ok {
				// Hub closed our channel (Unsubscribe / shutdown).
				close(out)
				return nil
			}
			me, keep := translate(ev)
			if !keep {
				continue
			}
			if want != nil && !want[me.GetType()] {
				continue
			}
			// Non-blocking handoff to the send goroutine: if its buffer is full the
			// consumer is too slow, so drop the newest event and count it rather
			// than stall the hub drain.
			select {
			case out <- me:
			default:
				s.dropped.Add(1)
			}
		}
	}
}

// kindSet returns the filter set, or nil when no filter is given (nil means
// "all kinds"). Empty strings are ignored; an all-empty request yields nil.
// Filter values are matched verbatim against the normalised kinds the stream
// emits ("connect"/"disconnect"/"alert"), so callers must use those exact tags.
func kindSet(kinds []string) map[string]bool {
	if len(kinds) == 0 {
		return nil
	}
	set := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		if k != "" {
			set[k] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// translate converts a live.Event into a monitor.v1 MonitorEvent. It returns
// keep=false for live events that are not session boundaries or alerts (e.g.
// HANDSHAKE_UP/DOWN keepalives, ERROR notices) — those are dashboard noise, not
// SIEM session/alert signal, so the SIEM stream skips them.
func translate(ev live.Event) (*monitorv1.MonitorEvent, bool) {
	kind := normalKind(ev.Type)
	if kind == "" {
		return nil, false
	}

	me := &monitorv1.MonitorEvent{Type: kind}
	if !ev.At.IsZero() {
		me.At = timestamppb.New(ev.At)
	}

	switch kind {
	case "alert":
		me.Alert = alertEvent(ev)
	default: // "connect" / "disconnect"
		me.Session = &monitorv1.SessionEvent{
			EventType:      kind,
			NodeId:         ev.NodeID,
			DeviceId:       ev.DeviceID,
			UserId:         ev.User,
			Protocol:       ev.Protocol,
			SourceIp:       ev.SourceIP,
			SourceEndpoint: ev.SourceEndpoint,
			// Reason carries through the live event — notably "stream-lost" on the
			// synthetic close-out a watcher publishes when a node's stream drops,
			// so a SIEM consumer sees those dangling sessions close. Empty on a
			// node-reported disconnect.
			Reason: ev.Reason,
			// Session byte deltas: set on a disconnect (the controller pairs the
			// node's connect/disconnect cumulative counters into a per-session
			// delta), 0 on a connect. The live Event carries them as uint64; the
			// proto field is int64, so clamp the (practically impossible)
			// >MaxInt64 case rather than wrapping to a negative.
			RxBytes: clampI64(ev.RxBytes),
			TxBytes: clampI64(ev.TxBytes),
		}
	}
	return me, true
}

// clampI64 narrows a uint64 byte count to the int64 the proto field carries,
// capping at math.MaxInt64 so a (practically impossible) overflow value never
// wraps to a negative byte count on the wire.
func clampI64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// normalKind maps a live.Event.Type to the normalised SIEM kind, or "" for an
// event type the SIEM stream does not surface. live.Event.Type carries the node
// proto EventType with the "EVENT_TYPE_" prefix trimmed (e.g. "PEER_CONNECTED"),
// or the literal "alert" for analytics alerts.
func normalKind(t string) string {
	switch t {
	case "PEER_CONNECTED":
		return "connect"
	case "PEER_DISCONNECTED":
		return "disconnect"
	case "alert":
		return "alert"
	default:
		return ""
	}
}

// alertEvent flattens the live event's alert payload into an AlertEvent. The hub
// carries the alert as an analytics.Alert (PublishAlert), so we type-assert it;
// an unexpected payload yields a minimal AlertEvent rather than a panic.
func alertEvent(ev live.Event) *monitorv1.AlertEvent {
	out := &monitorv1.AlertEvent{
		DeviceId:   ev.DeviceID,
		DetailJson: "{}",
	}
	a, ok := ev.Alert.(analytics.Alert)
	if !ok {
		return out
	}
	out.Id = a.ID
	out.Kind = a.Kind
	out.Severity = a.Severity
	out.DeviceId = a.DeviceID
	out.UserId = a.UserID
	out.SourceIps = a.SourceIPs
	if len(a.Detail) > 0 {
		if b, err := json.Marshal(a.Detail); err == nil {
			out.DetailJson = string(b)
		}
	}
	return out
}
