// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package live is coxswain's live plane (DESIGN §7): it holds each buoy node's
// WatchEvents stream open and fans events out through a Hub to subscribers.
// The admin WebSocket that serves browsers from the Hub lives in package api.
package live

import (
	"strings"
	"sync"
	"time"

	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
)

// subscriberBuffer is how many events a slow subscriber may fall behind before
// further events are dropped for it.
const subscriberBuffer = 64

// Event is a live node event in coxswain's own shape, ready for JSON fan-out.
type Event struct {
	NodeID   string    `json:"node_id"`
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Protocol string    `json:"protocol,omitempty"`
	PeerID   string    `json:"peer_id,omitempty"`
	Message  string    `json:"message,omitempty"`
}

// eventFrom converts a buoy proto event from a node into a live.Event.
func eventFrom(nodeID string, e *buoyv1.Event) Event {
	ev := Event{
		NodeID:  nodeID,
		Type:    strings.TrimPrefix(e.GetType().String(), "EVENT_TYPE_"),
		PeerID:  e.GetPeerId(),
		Message: e.GetMessage(),
	}
	if proto := strings.TrimPrefix(e.GetProtocol().String(), "PROTOCOL_"); proto != "UNSPECIFIED" {
		ev.Protocol = proto
	}
	if ts := e.GetAt(); ts != nil {
		ev.At = ts.AsTime()
	}
	return ev
}

// Hub fans live events from the node watchers out to WebSocket subscribers.
// It is safe for concurrent use.
type Hub struct {
	mu     sync.Mutex
	subs   map[int]chan Event
	nextID int
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[int]chan Event)}
}

// Subscribe registers a subscriber and returns its id and event channel.
func (h *Hub) Subscribe() (int, <-chan Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.nextID
	h.nextID++
	ch := make(chan Event, subscriberBuffer)
	h.subs[id] = ch
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.subs[id]; ok {
		delete(h.subs, id)
		close(ch)
	}
}

// Publish fans an event to every subscriber. A subscriber whose buffer is full
// is skipped — a slow browser must never stall the fleet.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribers reports the current subscriber count.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
