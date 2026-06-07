// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"sort"
	"time"
)

// ruleConcurrentSessions (warning) flags a device holding overlapping active
// sessions on concurrentMinNodes (2+) distinct nodes: a connect on node B that
// lands before the matching disconnect on node A. One device should ride one
// node at a time; two live sessions on different nodes means the profile is in
// use from two places.
//
// It reconstructs per-node session intervals from connect→disconnect pairs, then
// checks for any instant where intervals on 2+ distinct nodes overlap. The first
// overlap is the finding; evidence carries the nodes and the overlap window.
//
// Two robustness guards keep a dropped disconnect from fabricating overlap. An
// unmatched (still-open) connect is NOT believed to run to `now` — its
// disconnect may simply have been lost (node restart, dropped stream), which
// would make one stale connect overlap every later session forever. Instead it
// is capped at connect+maxOpenSessionAge. And because event timestamps are
// per-node wall-clock (see clockSkewTolerance), an overlap must exceed that
// tolerance to count — a sub-skew overlap is noise, not a real second session.
func ruleConcurrentSessions(_ context.Context, _ *sql.DB, dev deviceWindow, _ GeoResolver, now time.Time) []Finding {
	type interval struct {
		node       string
		start, end time.Time
	}

	// Build intervals per node. Pair each connect with the next disconnect on
	// the same node; an unmatched connect runs to `now` (still active).
	openOn := map[string]time.Time{} // node -> open connect start
	var intervals []interval
	for _, e := range dev.events {
		switch e.EventType {
		case "connect":
			if e.NodeID == "" {
				continue
			}
			// A second connect on a node without a disconnect: close the prior
			// one at this point and start fresh (keeps intervals well-formed).
			if start, ok := openOn[e.NodeID]; ok {
				intervals = append(intervals, interval{node: e.NodeID, start: start, end: e.At})
			}
			openOn[e.NodeID] = e.At
		case "disconnect":
			if e.NodeID == "" {
				continue
			}
			if start, ok := openOn[e.NodeID]; ok {
				intervals = append(intervals, interval{node: e.NodeID, start: start, end: e.At})
				delete(openOn, e.NodeID)
			}
		}
	}
	// A still-open connect is capped at start+maxOpenSessionAge, not `now`: its
	// disconnect may have been dropped, and believing it active to `now` would
	// let one stale connect manufacture overlap with every later session. A
	// genuinely active recent session (within maxOpenSessionAge of now) is still
	// covered, since its cap reaches at least up to now.
	for node, start := range openOn {
		end := start.Add(maxOpenSessionAge)
		if end.After(now) {
			end = now
		}
		intervals = append(intervals, interval{node: node, start: start, end: end})
	}
	if len(intervals) < concurrentMinNodes {
		return nil
	}

	// Sort by start; sweep for an overlap spanning 2+ distinct nodes.
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start.Before(intervals[j].start) })
	for i := range intervals {
		for j := i + 1; j < len(intervals); j++ {
			a, b := intervals[i], intervals[j]
			if a.node == b.node {
				continue
			}
			// Overlap = a.start < b's overlap window and b starts before a ends.
			overlapStart := maxTime(a.start, b.start)
			overlapEnd := minTime(a.end, b.end)
			// Require the overlap to exceed inter-node clock skew: a sub-skew
			// overlap is indistinguishable from two nodes' clocks disagreeing,
			// not a real second concurrent session.
			if overlapEnd.Sub(overlapStart) > clockSkewTolerance {
				nodes := []string{a.node, b.node}
				sort.Strings(nodes)
				f := Finding{
					Kind:     KindConcurrentSessions,
					Severity: SeverityWarning,
					DeviceID: dev.deviceID,
					UserID:   dev.userID,
					NodeID:   b.node,
					At:       overlapStart,
					DedupKey: KindConcurrentSessions + ":" + dev.deviceID,
					Detail: map[string]any{
						"nodes":           nodes,
						"overlap_start":   overlapStart.UTC().Format(time.RFC3339),
						"overlap_end":     overlapEnd.UTC().Format(time.RFC3339),
						"overlap_minutes": round2(overlapEnd.Sub(overlapStart).Minutes()),
					},
				}
				return []Finding{f}
			}
		}
	}
	return nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
