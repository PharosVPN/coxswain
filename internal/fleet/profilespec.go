// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// ErrInvalidProfileSpec is returned when a profile spec is malformed (no name,
// not exactly one egress, or an unknown protocol). Callers map it to 400.
var ErrInvalidProfileSpec = errors.New("fleet: invalid profile spec")

// Profile-spec protocols (entry transport). Mirror profile.Protocol* — kept as
// literals here so fleet doesn't import profile.
const (
	ProtoAmneziaWG   = "amneziawg"
	ProtoXRayReality = "xray-reality"
	// ProtoBoth offers both protocols on the profile; the client picks at connect.
	ProtoBoth = "both"
)

// ProfileSpec is the admin-created "profile" (the `profile_specs` table): a
// named connection config for a (user, device) — an egress (a multi-hop Path or
// a single Node), an optional subset of the entry node's IP pool, and one
// data-plane protocol. A device may have several. Provisioning turns a spec into
// the device's own keys + peers; the sealed sync bundle carries the rendered
// profiles[].
type ProfileSpec struct {
	ID       string
	UserID   string
	DeviceID string
	Name     string
	// Egress: exactly one of PathID (cascade) or NodeID (direct single node).
	PathID string
	NodeID string
	// EntryIPs is the subset of the entry node's IP pool the client may enter
	// on; empty = all of the entry node's IPs.
	EntryIPs []string
	// Protocol is the entry transport: ProtoAmneziaWG or ProtoXRayReality.
	Protocol  string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

const profileSpecColumns = `id, user_id, device_id, name, path_id, node_id,
	entry_ips, protocol, version, created_at, updated_at`

// Validate checks a spec is well-formed: a name, exactly one egress, a known
// protocol, and (for direct) a node or (for cascade) a path.
func (s ProfileSpec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("%w: name required", ErrInvalidProfileSpec)
	}
	if s.UserID == "" || s.DeviceID == "" {
		return fmt.Errorf("%w: user and device required", ErrInvalidProfileSpec)
	}
	if (s.PathID == "") == (s.NodeID == "") {
		return fmt.Errorf("%w: set exactly one of path or node as the egress", ErrInvalidProfileSpec)
	}
	if s.Protocol != ProtoAmneziaWG && s.Protocol != ProtoXRayReality && s.Protocol != ProtoBoth {
		return fmt.Errorf("%w: unknown protocol %q", ErrInvalidProfileSpec, s.Protocol)
	}
	return nil
}

// CreateProfileSpec validates and inserts a profile spec. ID, Version and
// timestamps are filled in. The stored spec is returned.
func CreateProfileSpec(ctx context.Context, db *sql.DB, s ProfileSpec) (ProfileSpec, error) {
	if err := s.Validate(); err != nil {
		return ProfileSpec{}, err
	}
	if s.ID == "" {
		s.ID = idgen.New("pspec")
	}
	now := time.Now().UTC()
	s.Version = 1
	s.CreatedAt, s.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO profile_specs (`+profileSpecColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.DeviceID, s.Name, s.PathID, s.NodeID,
		joinIPs(s.EntryIPs), s.Protocol, s.Version, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return ProfileSpec{}, fmt.Errorf("create profile spec: %w", err)
	}
	return s, nil
}

// GetProfileSpec returns one spec by id, or ErrNotFound.
func GetProfileSpec(ctx context.Context, db *sql.DB, id string) (ProfileSpec, error) {
	row := db.QueryRowContext(ctx, `SELECT `+profileSpecColumns+` FROM profile_specs WHERE id = ?`, id)
	s, err := scanProfileSpec(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ProfileSpec{}, ErrNotFound
	}
	return s, err
}

// ListProfileSpecs returns every profile spec, oldest first.
func ListProfileSpecs(ctx context.Context, db *sql.DB) ([]ProfileSpec, error) {
	return queryProfileSpecs(ctx, db, `ORDER BY created_at`)
}

// ListProfileSpecsByDevice returns a device's profile specs, oldest first.
func ListProfileSpecsByDevice(ctx context.Context, db *sql.DB, deviceID string) ([]ProfileSpec, error) {
	return queryProfileSpecs(ctx, db, `WHERE device_id = ? ORDER BY created_at`, deviceID)
}

// ListProfileSpecsByUser returns a user's profile specs across devices.
func ListProfileSpecsByUser(ctx context.Context, db *sql.DB, userID string) ([]ProfileSpec, error) {
	return queryProfileSpecs(ctx, db, `WHERE user_id = ? ORDER BY created_at`, userID)
}

// ListProfileSpecsByPath returns the cascade profile specs bound to a path
// (path_id set), oldest first — the per-profile equivalent of device_exits. The
// cascade coordinator routes each one's entry tunnel IP through the path.
func ListProfileSpecsByPath(ctx context.Context, db *sql.DB, pathID string) ([]ProfileSpec, error) {
	if pathID == "" {
		return nil, nil
	}
	return queryProfileSpecs(ctx, db, `WHERE path_id = ? ORDER BY created_at`, pathID)
}

// DeleteProfileSpec removes a spec. A missing row yields ErrNotFound. (Its peers
// are cleared by the caller/provisioning, like device peers.)
func DeleteProfileSpec(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM profile_specs WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete profile spec: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func queryProfileSpecs(ctx context.Context, db *sql.DB, where string, args ...any) ([]ProfileSpec, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+profileSpecColumns+` FROM profile_specs `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list profile specs: %w", err)
	}
	defer rows.Close()
	var out []ProfileSpec
	for rows.Next() {
		s, err := scanProfileSpec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanProfileSpec(s rowScanner) (ProfileSpec, error) {
	var (
		ps       ProfileSpec
		entryIPs string
	)
	err := s.Scan(&ps.ID, &ps.UserID, &ps.DeviceID, &ps.Name, &ps.PathID, &ps.NodeID,
		&entryIPs, &ps.Protocol, &ps.Version, &ps.CreatedAt, &ps.UpdatedAt)
	if err != nil {
		return ProfileSpec{}, err
	}
	ps.EntryIPs = splitIPs(entryIPs)
	return ps, nil
}
