// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package live

import (
	"testing"
	"time"

	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHubFanOut(t *testing.T) {
	h := NewHub()
	_, ch1 := h.Subscribe()
	_, ch2 := h.Subscribe()
	if h.Subscribers() != 2 {
		t.Fatalf("subscribers: got %d want 2", h.Subscribers())
	}

	h.Publish(Event{NodeID: "n1", Type: "HANDSHAKE_UP"})

	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.NodeID != "n1" {
				t.Errorf("subscriber %d: got %q", i, e.NodeID)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d received no event", i)
		}
	}
}

func TestHubUnsubscribe(t *testing.T) {
	h := NewHub()
	id, ch := h.Subscribe()
	h.Unsubscribe(id)

	if _, ok := <-ch; ok {
		t.Error("channel not closed after Unsubscribe")
	}
	if h.Subscribers() != 0 {
		t.Errorf("subscribers: got %d want 0", h.Subscribers())
	}
	h.Publish(Event{NodeID: "n1"}) // must not panic on a closed subscriber
}

func TestHubDropsSlowSubscriber(t *testing.T) {
	h := NewHub()
	_, ch := h.Subscribe()

	// Publish well past the buffer; a slow subscriber must not block Publish.
	for range subscriberBuffer + 50 {
		h.Publish(Event{NodeID: "n1"})
	}
	if len(ch) != subscriberBuffer {
		t.Errorf("buffered events: got %d want %d", len(ch), subscriberBuffer)
	}
}

func TestEventFrom(t *testing.T) {
	at := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	got := eventFrom("nod_x", &buoyv1.Event{
		At:       timestamppb.New(at),
		Type:     buoyv1.EventType_EVENT_TYPE_HANDSHAKE_UP,
		Protocol: buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
		PeerId:   "peer-1",
		Message:  "handshake",
	})
	if got.NodeID != "nod_x" || got.Type != "HANDSHAKE_UP" {
		t.Errorf("node/type: got %+v", got)
	}
	if got.Protocol != "AMNEZIAWG" {
		t.Errorf("protocol: got %q", got.Protocol)
	}
	if got.PeerID != "peer-1" || got.Message != "handshake" {
		t.Errorf("peer/message: got %+v", got)
	}
	if !got.At.Equal(at) {
		t.Errorf("timestamp: got %v want %v", got.At, at)
	}

	// An unspecified protocol is dropped rather than rendered as a string.
	bare := eventFrom("nod_x", &buoyv1.Event{Type: buoyv1.EventType_EVENT_TYPE_ERROR})
	if bare.Protocol != "" {
		t.Errorf("unspecified protocol: got %q want empty", bare.Protocol)
	}
}
