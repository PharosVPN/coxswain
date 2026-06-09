// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package db

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestOpenAndMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	if err := Migrate(conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Migrate is idempotent.
	if err := Migrate(conn); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	want := []string{
		"admins", "alerts", "api_tokens", "audit_log", "bootstrap_tokens", "ca", "connection_events",
		"control_paths", "controller_cert", "device_certs", "device_exits", "devices", "enrollment_tickets",
		"metrics_samples", "node_certs", "node_links", "nodes", "path_hops", "paths", "peers",
		"profile_signing_key", "profile_specs", "profiles", "relays", "servers", "service_certs",
		"sessions", "ssh_identity", "users",
	}
	rows, err := conn.Query(
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'goose_%' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("query tables: %v", err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("tables: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tables: got %v want %v", got, want)
		}
	}
}
