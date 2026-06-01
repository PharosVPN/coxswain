// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package live

import (
	"context"
	"log/slog"
	"time"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/fleet"
)

const (
	watchBackoffMin = 2 * time.Second
	watchBackoffMax = 60 * time.Second
)

// WatchNode holds a buoy node's WatchEvents stream open, publishing every
// event to the hub. It reconnects with capped exponential backoff and returns
// only when ctx is cancelled — a controller staying connected through node
// restarts is the point of the live plane.
func WatchNode(ctx context.Context, dialer *control.Dialer, node fleet.Node, hub *Hub) {
	backoff := watchBackoffMin
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		err := streamNode(ctx, dialer, node, hub)
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
// until it ends or errors.
func streamNode(ctx context.Context, dialer *control.Dialer, node fleet.Node, hub *Hub) error {
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
		hub.Publish(eventFrom(node.ID, ev))
	}
}
