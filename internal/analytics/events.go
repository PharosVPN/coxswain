// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"
)

// event is one connection_events row the engine reasons over. Only the columns
// the rules need are loaded.
type event struct {
	At        time.Time
	NodeID    string
	DeviceID  string
	UserID    string
	Protocol  string
	EventType string // "connect" | "disconnect" | "handshake"
	SourceIP  string
	// RxBytes/TxBytes are the session's transferred byte deltas, stamped on the
	// disconnect row (connect rows carry 0). RxBytes is the node's awg transfer-rx
	// = the client's UPLOAD (data leaving the client toward the tunnel); TxBytes
	// is the client's download. The data_volume rule reads RxBytes (the exfil
	// direction).
	RxBytes uint64
	TxBytes uint64
}

// deviceWindow is one device's recent events, oldest-first, ready for the rules.
// userID is the device's resolved owner (the most recent non-empty user_id seen
// in the window), carried onto every alert for that device.
type deviceWindow struct {
	deviceID string
	userID   string
	events   []event // ascending by At
}

// loadDeviceWindows loads connection_events in [since, now] with a non-null
// device_id, grouped by device and sorted oldest-first within each group. Infra
// links (NULL device_id) are excluded at the SQL level, so no rule ever sees
// them.
func loadDeviceWindows(ctx context.Context, db *sql.DB, since, now time.Time) ([]deviceWindow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT at, node_id, device_id, user_id, protocol, event_type, source_ip, rx_bytes, tx_bytes
		FROM connection_events
		WHERE device_id IS NOT NULL AND device_id != ''
		  AND at >= ? AND at <= ?
		ORDER BY device_id ASC, at ASC, id ASC`,
		since.UTC(), now.UTC())
	if err != nil {
		return nil, fmt.Errorf("analytics: load events: %w", err)
	}
	defer rows.Close()

	byDevice := map[string]*deviceWindow{}
	var order []string
	for rows.Next() {
		var (
			e      event
			userID sql.NullString
		)
		if err := rows.Scan(&e.At, &e.NodeID, &e.DeviceID, &userID,
			&e.Protocol, &e.EventType, &e.SourceIP, &e.RxBytes, &e.TxBytes); err != nil {
			return nil, err
		}
		e.UserID = userID.String
		dw, ok := byDevice[e.DeviceID]
		if !ok {
			dw = &deviceWindow{deviceID: e.DeviceID}
			byDevice[e.DeviceID] = dw
			order = append(order, e.DeviceID)
		}
		if e.UserID != "" {
			dw.userID = e.UserID // last writer wins; rows are time-ascending
		}
		dw.events = append(dw.events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]deviceWindow, 0, len(order))
	for _, id := range order {
		out = append(out, *byDevice[id])
	}
	return out, nil
}

// priorCountries returns the set of country codes a device connected from
// STRICTLY BEFORE `before`, over the full connection_events history (not just
// the sweep window) — the baseline the new_geo rule compares against. It needs
// a resolver to map historical source IPs to countries.
func priorCountries(ctx context.Context, db *sql.DB, geo GeoResolver, deviceID string, before time.Time) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_ip
		FROM connection_events
		WHERE device_id = ? AND event_type = 'connect'
		  AND source_ip != '' AND at < ?`,
		deviceID, before.UTC())
	if err != nil {
		return nil, fmt.Errorf("analytics: prior countries: %w", err)
	}
	defer rows.Close()

	countries := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		if loc, ok := geo.Lookup(ip); ok && loc.CountryCode != "" {
			countries[loc.CountryCode] = true
		}
	}
	return countries, rows.Err()
}

// connectsBySourceIP groups a window's connect events by source IP, returning
// the distinct IPs (sorted) and, for each, the events at that IP. Empty source
// IPs are skipped.
func connectsBySourceIP(evs []event) (ips []string, byIP map[string][]event) {
	byIP = map[string][]event{}
	for _, e := range evs {
		if e.EventType != "connect" || e.SourceIP == "" {
			continue
		}
		if _, ok := byIP[e.SourceIP]; !ok {
			ips = append(ips, e.SourceIP)
		}
		byIP[e.SourceIP] = append(byIP[e.SourceIP], e)
	}
	sort.Strings(ips)
	return ips, byIP
}
