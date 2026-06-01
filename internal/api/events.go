// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

const wsWriteTimeout = 10 * time.Second

// handleEvents upgrades to a WebSocket and streams live events to the browser.
// It runs behind requireAuth; the SameSite session cookie also keeps a
// cross-site page from opening an authenticated stream.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()

	// CloseRead drains client frames and cancels ctx when the browser leaves.
	ctx := c.CloseRead(r.Context())

	id, events := s.hub.Subscribe()
	defer s.hub.Unsubscribe(id)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
			err = c.Write(writeCtx, websocket.MessageText, data)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
