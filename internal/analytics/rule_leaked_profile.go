// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"time"
)

// ruleLeakedProfile (warning) flags a device whose profile appears to be shared
// or leaked: connect events from leakedProfileMinIPs (2+) distinct source IPs
// within leakedProfileWindow (10m). A single profile bundle is meant for one
// device on one connection; simultaneous use from multiple public IPs is the
// headline indicator that the sealed bundle escaped.
//
// It slides the window over the connect events and fires when any window holds
// connects from 2+ distinct IPs. Dedup is per-device (one open leaked_profile
// alert per device); evidence carries the IPs, the nodes, and the times.
func ruleLeakedProfile(_ context.Context, _ *sql.DB, dev deviceWindow, _ GeoResolver, _ time.Time) []Finding {
	// Connect events only, time-ascending (the window is already sorted).
	var connects []event
	for _, e := range dev.events {
		if e.EventType == "connect" && e.SourceIP != "" {
			connects = append(connects, e)
		}
	}
	if len(connects) < leakedProfileMinIPs {
		return nil
	}

	// Slide a leakedProfileWindow span: for each start event, gather the
	// distinct IPs seen until the window closes. The first start that reaches
	// the threshold is the finding.
	for i := range connects {
		windowEnd := connects[i].At.Add(leakedProfileWindow)
		ipSet := map[string]bool{}
		nodeSet := map[string]bool{}
		var times []string
		var firstUser string
		for j := i; j < len(connects); j++ {
			if connects[j].At.After(windowEnd) {
				break
			}
			ipSet[connects[j].SourceIP] = true
			if connects[j].NodeID != "" {
				nodeSet[connects[j].NodeID] = true
			}
			times = append(times, connects[j].At.UTC().Format(time.RFC3339))
			if firstUser == "" {
				firstUser = connects[j].UserID
			}
		}
		if len(ipSet) >= leakedProfileMinIPs {
			ips := keys(ipSet)
			f := Finding{
				Kind:      KindLeakedProfile,
				Severity:  SeverityWarning,
				DeviceID:  dev.deviceID,
				UserID:    dev.userID,
				SourceIPs: ips,
				At:        connects[i].At,
				// One open alert per device for this kind: a leaked profile is a
				// device-level condition, not per-IP-pair.
				DedupKey: KindLeakedProfile + ":" + dev.deviceID,
				Detail: map[string]any{
					"distinct_ips": len(ips),
					"source_ips":   ips,
					"nodes":        keys(nodeSet),
					"window":       leakedProfileWindow.String(),
					"first_seen":   connects[i].At.UTC().Format(time.RFC3339),
					"times":        times,
				},
			}
			return []Finding{f}
		}
	}
	return nil
}
