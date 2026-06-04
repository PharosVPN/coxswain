// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// ErrServerInUse is returned when deleting a server that still has node or
// relay roles deployed onto it.
var ErrServerInUse = errors.New("fleet: server still has deployed components")

// Server is a machine coxswain owns (the `servers` table): a host reached over
// SSH (or, for the controller's own host, locally) onto which node/relay roles
// are deployed. A server is onboarded once with a one-time password; coxswain
// installs its SSH key and pins the host key, then uses key auth (DESIGN §5).
type Server struct {
	ID      string
	Name    string
	Region  string
	SSHHost string
	SSHUser string
	SSHPort int
	// SSHHostKey pins the host's SSH key, captured at bootstrap (TOFU).
	SSHHostKey string
	// IsSelf marks the controller's own host: deploys run locally, not over SSH.
	IsSelf bool
	Status string
	// Route is the ordered relay hops coxswain dials this server through on every
	// channel (onboard/deploy SSH + node gRPC); empty means direct (the default).
	Route     []string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

const serverColumns = `id, name, region, ssh_host, ssh_user, ssh_port,
	ssh_host_key, is_self, status, route, version, created_at, updated_at`

// routeToCSV / routeFromCSV (de)serialize the ordered relay-id hop list to the
// single `route` column. Empty list ⇄ empty string (direct).
func routeToCSV(route []string) string { return strings.Join(route, ",") }

func routeFromCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// CreateServer inserts a new server. ID and Status are filled in if empty and
// SSHPort defaults to 22. The stored Server is returned.
func CreateServer(ctx context.Context, db *sql.DB, s Server) (Server, error) {
	if s.ID == "" {
		s.ID = idgen.New("srv")
	}
	if s.Status == "" {
		s.Status = StatusPending
	}
	if s.SSHPort == 0 {
		s.SSHPort = 22
	}
	now := time.Now().UTC()
	s.Version = 1
	s.CreatedAt, s.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO servers (`+serverColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Name, s.Region, s.SSHHost, s.SSHUser, s.SSHPort,
		s.SSHHostKey, boolToInt(s.IsSelf), s.Status, routeToCSV(s.Route), s.Version, s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return Server{}, fmt.Errorf("create server: %w", err)
	}
	return s, nil
}

// GetServer returns the server with the given ID, or ErrNotFound.
func GetServer(ctx context.Context, db *sql.DB, id string) (Server, error) {
	row := db.QueryRowContext(ctx, `SELECT `+serverColumns+` FROM servers WHERE id = ?`, id)
	s, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return s, err
}

// GetServerByHost returns the server with the given SSH host, or ErrNotFound.
// Used to make re-onboarding the same machine idempotent.
func GetServerByHost(ctx context.Context, db *sql.DB, host string) (Server, error) {
	row := db.QueryRowContext(ctx, `SELECT `+serverColumns+` FROM servers WHERE ssh_host = ? ORDER BY created_at LIMIT 1`, host)
	s, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return s, err
}

// GetSelfServer returns the controller's own host record, or ErrNotFound.
func GetSelfServer(ctx context.Context, db *sql.DB) (Server, error) {
	row := db.QueryRowContext(ctx, `SELECT `+serverColumns+` FROM servers WHERE is_self = 1`)
	s, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	return s, err
}

// ListServers returns every server, oldest first.
func ListServers(ctx context.Context, db *sql.DB) ([]Server, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+serverColumns+` FROM servers ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	defer rows.Close()

	var out []Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdateServer writes s back with optimistic concurrency (version must match).
// A stale version yields ErrStaleVersion; a missing row yields ErrNotFound.
func UpdateServer(ctx context.Context, db *sql.DB, s Server) (Server, error) {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE servers SET name = ?, region = ?, ssh_host = ?, ssh_user = ?,
		        ssh_port = ?, ssh_host_key = ?, is_self = ?, status = ?, route = ?,
		        version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		s.Name, s.Region, s.SSHHost, s.SSHUser, s.SSHPort, s.SSHHostKey,
		boolToInt(s.IsSelf), s.Status, routeToCSV(s.Route), now, s.ID, s.Version)
	if err != nil {
		return Server{}, fmt.Errorf("update server: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Server{}, err
	}
	if affected == 0 {
		if _, gErr := GetServer(ctx, db, s.ID); errors.Is(gErr, ErrNotFound) {
			return Server{}, ErrNotFound
		}
		return Server{}, ErrStaleVersion
	}
	s.Version++
	s.UpdatedAt = now
	return s, nil
}

// SetServerStatus updates a server's status unconditionally (no version check),
// bumping version and updated_at. A missing row yields ErrNotFound.
func SetServerStatus(ctx context.Context, db *sql.DB, id, status string) error {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE servers SET status = ?, version = version + 1, updated_at = ? WHERE id = ?`,
		status, now, id)
	if err != nil {
		return fmt.Errorf("set server status: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteServer removes a server. It refuses (ErrServerInUse) while any node or
// relay still references it; a missing row yields ErrNotFound.
func DeleteServer(ctx context.Context, db *sql.DB, id string) error {
	var refs int
	if err := db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM nodes WHERE server_id = ?) +
		        (SELECT COUNT(*) FROM relays WHERE server_id = ?)`, id, id).Scan(&refs); err != nil {
		return fmt.Errorf("check server refs: %w", err)
	}
	if refs > 0 {
		return ErrServerInUse
	}
	res, err := db.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete server: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func scanServer(s rowScanner) (Server, error) {
	var (
		srv    Server
		isSelf int
		route  string
	)
	err := s.Scan(&srv.ID, &srv.Name, &srv.Region, &srv.SSHHost, &srv.SSHUser,
		&srv.SSHPort, &srv.SSHHostKey, &isSelf, &srv.Status, &route, &srv.Version,
		&srv.CreatedAt, &srv.UpdatedAt)
	if err != nil {
		return Server{}, err
	}
	srv.IsSelf = isSelf != 0
	srv.Route = routeFromCSV(route)
	return srv, nil
}

// SetServerRoute replaces a server's control-plane provision route (the ordered
// relay hops it is dialed through; empty = direct), bumping version and
// updated_at. A missing row yields ErrNotFound.
func SetServerRoute(ctx context.Context, db *sql.DB, id string, route []string) error {
	res, err := db.ExecContext(ctx,
		`UPDATE servers SET route = ?, version = version + 1, updated_at = ? WHERE id = ?`,
		routeToCSV(route), time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("set server route: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
