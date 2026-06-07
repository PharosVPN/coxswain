// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
)

// ruleRevokedProfileActive (critical) flags a device whose account-side status
// is no longer active (revoked/disabled) yet is still connecting: a connect
// event inside the sweep window for a device the operator has already cut off.
// This is the highest-signal access-control violation — a profile that should
// have stopped working is still in use, meaning the bundle was extracted before
// revocation and is being replayed, or revocation has not propagated.
//
// The device status lives in the `devices` table (account package), not in
// connection_events, so the rule looks it up directly. Any status other than
// active (the table's default) is treated as cut off. Dedup is per-device: one
// open alert per revoked device, refreshed (not duplicated) while it keeps
// connecting.
func ruleRevokedProfileActive(ctx context.Context, db *sql.DB, dev deviceWindow, _ GeoResolver, _ time.Time) []Finding {
	// Most recent connect in the window — the evidence "it is still connecting".
	var lastConnect *event
	for i := range dev.events {
		if dev.events[i].EventType == "connect" {
			lastConnect = &dev.events[i] // ascending order: last writer wins
		}
	}
	if lastConnect == nil {
		return nil // no connect in the window — nothing live to flag
	}

	var status string
	err := db.QueryRowContext(ctx,
		`SELECT status FROM devices WHERE id = ?`, dev.deviceID).Scan(&status)
	switch {
	case err == sql.ErrNoRows:
		// Device row deleted but events linger — not the condition this rule
		// targets (a *revoked* device still on file). Leave it to other rules.
		return nil
	case err != nil:
		slog.Warn("analytics: revoked_profile_active device lookup failed", "device", dev.deviceID, "err", err)
		return nil
	}
	if status == account.StatusActive {
		return nil // active device connecting is normal
	}

	return []Finding{{
		Kind:      KindRevokedProfileActive,
		Severity:  SeverityCritical,
		DeviceID:  dev.deviceID,
		UserID:    dev.userID,
		NodeID:    lastConnect.NodeID,
		SourceIPs: nonEmpty(lastConnect.SourceIP),
		At:        lastConnect.At,
		// One open alert per cut-off device.
		DedupKey: KindRevokedProfileActive + ":" + dev.deviceID,
		Detail: map[string]any{
			"device_status":     status,
			"last_connect":      lastConnect.At.UTC().Format(time.RFC3339),
			"last_connect_node": lastConnect.NodeID,
			"source_ip":         lastConnect.SourceIP,
		},
	}}
}
