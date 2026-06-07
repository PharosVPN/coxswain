// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"
)

// ruleAuthFailureSpike (warning) flags a burst of failed logins from one source
// IP — the signature of credential stuffing or a brute-force attempt against the
// admin console. It reads auth.login_failed rows from the audit_log (where every
// failed login is recorded, the attacker-controlled username tucked into the
// JSON detail), groups them by source IP, and fires when any IP produces at
// least authFailureThreshold (5) failures inside any authFailureWindow (10m)
// span.
//
// This is a fleet-wide rule, not per-device: a failed login has no device yet
// (auth precedes device identity), so it scans the audit table directly and the
// alert is IP-scoped, with device_id left null. Dedup is per source IP: one open
// alert per attacking IP, refreshed while the burst continues. Evidence carries
// the count, the window, and the distinct attempted usernames.
func ruleAuthFailureSpike(ctx context.Context, db *sql.DB, since, now time.Time) []Finding {
	rows, err := db.QueryContext(ctx, `
		SELECT at, source_ip, detail FROM audit_log
		WHERE action = 'auth.login_failed' AND at >= ? AND at <= ?
		ORDER BY source_ip ASC, at ASC`,
		since.UTC(), now.UTC())
	if err != nil {
		slog.Warn("analytics: auth_failure_spike query failed", "err", err)
		return nil
	}
	defer rows.Close()

	type attempt struct {
		at       time.Time
		username string
	}
	byIP := map[string][]attempt{}
	var order []string
	for rows.Next() {
		var (
			at        time.Time
			sourceIP  string
			detailStr string
		)
		if err := rows.Scan(&at, &sourceIP, &detailStr); err != nil {
			slog.Warn("analytics: auth_failure_spike scan failed", "err", err)
			return nil
		}
		if sourceIP == "" {
			continue // can't attribute a spike to an unknown origin
		}
		if _, ok := byIP[sourceIP]; !ok {
			order = append(order, sourceIP)
		}
		byIP[sourceIP] = append(byIP[sourceIP], attempt{at: at.UTC(), username: attemptedUsername(detailStr)})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("analytics: auth_failure_spike rows err", "err", err)
		return nil
	}

	var out []Finding
	for _, ip := range order {
		attempts := byIP[ip] // already time-ascending from the ORDER BY
		if len(attempts) < authFailureThreshold {
			continue
		}
		// Slide an authFailureWindow span: the first start that gathers
		// authFailureThreshold failures is the spike.
		for i := range attempts {
			windowEnd := attempts[i].at.Add(authFailureWindow)
			var count int
			users := map[string]bool{}
			var lastAt time.Time
			for j := i; j < len(attempts); j++ {
				if attempts[j].at.After(windowEnd) {
					break
				}
				count++
				lastAt = attempts[j].at
				if attempts[j].username != "" {
					users[attempts[j].username] = true
				}
			}
			if count >= authFailureThreshold {
				out = append(out, Finding{
					Kind:      KindAuthFailureSpike,
					Severity:  SeverityWarning,
					SourceIPs: []string{ip},
					At:        lastAt,
					// One open alert per attacking source IP.
					DedupKey: KindAuthFailureSpike + ":" + ip,
					Detail: map[string]any{
						"source_ip":           ip,
						"failure_count":       count,
						"window":              authFailureWindow.String(),
						"first_failure":       attempts[i].at.Format(time.RFC3339),
						"last_failure":        lastAt.Format(time.RFC3339),
						"attempted_usernames": keys(users),
					},
				})
				break // one finding per IP per sweep
			}
		}
	}
	return out
}

// attemptedUsername pulls the submitted username out of an auth.login_failed
// audit row's JSON detail blob (api.auditLoginFailed writes {"username": ...}).
// A malformed or absent detail yields "".
func attemptedUsername(detailJSON string) string {
	if detailJSON == "" {
		return ""
	}
	var d struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal([]byte(detailJSON), &d); err != nil {
		return ""
	}
	return d.Username
}
