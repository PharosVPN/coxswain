// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// detectPublicIP best-effort resolves the controller host's public IP by asking
// a couple of echo services, so the controller can be plotted on the map. It
// returns "" on any failure (offline, blocked egress, or an enterprise setup
// with no public IP) — the UI then falls back to a manually set location.
func detectPublicIP(ctx context.Context) string {
	client := &http.Client{Timeout: 4 * time.Second}
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}
