// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package fleet is coxswain's domain layer over the buoy node inventory and the
// one-time bootstrap tokens used to enrol new nodes (DESIGN §5).
package fleet

import "errors"

var (
	// ErrNotFound is returned when a record does not exist.
	ErrNotFound = errors.New("fleet: record not found")
	// ErrStaleVersion is returned when an update carries a version older than
	// the stored row — the optimistic-concurrency check in DESIGN §7.
	ErrStaleVersion = errors.New("fleet: record changed by another writer")
)

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}
