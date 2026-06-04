// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
	"github.com/PharosVPN/coxswain/internal/wg"
)

// Node lifecycle states.
const (
	StatusPending      = "pending"      // record created, no VM yet
	StatusProvisioning = "provisioning" // cloud VM being created
	StatusEnrolling    = "enrolling"    // VM up, bootstrap token outstanding
	StatusActive       = "active"       // enrolled, under coxswain's control
	StatusStopped      = "stopped"      // VM stopped (pre-positioned idle node)
	StatusUnreachable  = "unreachable"  // missed control-plane heartbeats
	StatusError        = "error"        // provisioning or enrollment failed
)

// Node is one node in the fleet inventory (the `nodes` table).
type Node struct {
	ID       string
	Name     string
	Region   string
	PublicIP string
	// EndpointIPs is the node's AmneziaWG endpoint IP pool (decision 17).
	// Empty means "use PublicIP only".
	EndpointIPs []string
	ControlAddr string
	CloudID     string
	// ServerID links this node to the server (machine) it was deployed onto.
	// Empty for legacy inline-SSH nodes onboarded before the server layer.
	ServerID string
	// SSHHost, SSHUser, SSHPort are how coxswain reaches the node to install and
	// update the node agent (DESIGN §5). SSH is a deployment channel only.
	SSHHost string
	SSHUser string
	SSHPort int
	// SSHHostKey pins the node's SSH host key, captured on first connect.
	SSHHostKey string
	// AgentVersion is the node build last deployed to the node.
	AgentVersion string
	// WGPublicKey is the node's AmneziaWG server public key, reported by node.
	WGPublicKey string
	// Obfuscation is the node's per-node AmneziaWG obfuscation parameter set,
	// reported by node alongside WGPublicKey (DESIGN §3). Zero until reported.
	Obfuscation wg.Obfuscation
	// Forwarding, Masquerade, Isolation are the node's network policy
	// (DESIGN §3, decision 16), set per node from the admin UI.
	Forwarding bool
	Masquerade bool
	Isolation  bool
	Status     string
	// ConfigRevision is the last PushConfig revision coxswain assigned to this
	// node (B2 — node rejects stale revisions with FailedPrecondition).
	ConfigRevision int64
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const nodeColumns = `id, name, region, public_ip, endpoint_ips, control_addr, cloud_id,
	ssh_host, ssh_user, ssh_port, ssh_host_key, agent_version, wg_public_key,
	wg_obfuscation, forwarding, masquerade, isolation, config_revision,
	status, version, created_at, updated_at, server_id`

// marshalObfuscation encodes an obfuscation set for the wg_obfuscation column.
// A zero set stores as the empty string ("not reported yet").
func marshalObfuscation(o wg.Obfuscation) string {
	if o.IsZero() {
		return ""
	}
	b, _ := json.Marshal(o)
	return string(b)
}

// unmarshalObfuscation decodes a wg_obfuscation column value.
func unmarshalObfuscation(s string) (wg.Obfuscation, error) {
	var o wg.Obfuscation
	if s == "" {
		return o, nil
	}
	if err := json.Unmarshal([]byte(s), &o); err != nil {
		return wg.Obfuscation{}, fmt.Errorf("decode node obfuscation: %w", err)
	}
	return o, nil
}

// EndpointAddrs returns the node's endpoint IP pool, falling back to the
// primary public IP when no pool is configured.
func (n Node) EndpointAddrs() []string {
	if len(n.EndpointIPs) > 0 {
		return n.EndpointIPs
	}
	if n.PublicIP != "" {
		return []string{n.PublicIP}
	}
	return nil
}

func joinIPs(ips []string) string { return strings.Join(ips, ",") }
func splitIPs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// CreateNode inserts a new node. ID and Status are filled in if empty, SSHPort
// defaults to 22, Version is set to 1, and the network policy starts at the
// standard internet-egress posture (forwarding + masquerade on). The stored
// Node is returned.
func CreateNode(ctx context.Context, db *sql.DB, n Node) (Node, error) {
	if n.ID == "" {
		n.ID = idgen.New("nod")
	}
	if n.Status == "" {
		n.Status = StatusPending
	}
	if n.SSHPort == 0 {
		n.SSHPort = 22
	}
	// Network policy is configured after onboarding, via UpdateNode.
	n.Forwarding, n.Masquerade, n.Isolation = true, true, false
	now := time.Now().UTC()
	n.Version = 1
	n.CreatedAt, n.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO nodes (`+nodeColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.Region, n.PublicIP, joinIPs(n.EndpointIPs), n.ControlAddr, n.CloudID,
		n.SSHHost, n.SSHUser, n.SSHPort, n.SSHHostKey, n.AgentVersion, n.WGPublicKey,
		marshalObfuscation(n.Obfuscation), n.Forwarding, n.Masquerade, n.Isolation,
		n.ConfigRevision, n.Status, n.Version, n.CreatedAt, n.UpdatedAt, n.ServerID)
	if err != nil {
		return Node{}, fmt.Errorf("create node: %w", err)
	}
	return n, nil
}

// GetNode returns the node with the given ID, or ErrNotFound.
func GetNode(ctx context.Context, db *sql.DB, id string) (Node, error) {
	row := db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id)
	n, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// ListNodes returns every node, oldest first.
func ListNodes(ctx context.Context, db *sql.DB) ([]Node, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNode writes n back, enforcing optimistic concurrency: the update
// succeeds only if n.Version matches the stored row. On success the version is
// bumped and the refreshed Node returned. A stale version yields
// ErrStaleVersion; a missing row yields ErrNotFound.
func UpdateNode(ctx context.Context, db *sql.DB, n Node) (Node, error) {
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE nodes SET name = ?, region = ?, public_ip = ?, endpoint_ips = ?,
		        control_addr = ?, cloud_id = ?, ssh_host = ?, ssh_user = ?,
		        ssh_port = ?, ssh_host_key = ?, agent_version = ?, wg_public_key = ?,
		        wg_obfuscation = ?, forwarding = ?, masquerade = ?, isolation = ?,
		        status = ?, server_id = ?, version = version + 1, updated_at = ?
		 WHERE id = ? AND version = ?`,
		n.Name, n.Region, n.PublicIP, joinIPs(n.EndpointIPs), n.ControlAddr, n.CloudID,
		n.SSHHost, n.SSHUser, n.SSHPort, n.SSHHostKey, n.AgentVersion, n.WGPublicKey,
		marshalObfuscation(n.Obfuscation), n.Forwarding, n.Masquerade, n.Isolation,
		n.Status, n.ServerID, now, n.ID, n.Version)
	// NOTE: ConfigRevision is updated only via NextNodeConfigRevision; an
	// UpdateNode caller is reconciling node metadata, not pushing config.
	if err != nil {
		return Node{}, fmt.Errorf("update node: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Node{}, err
	}
	if affected == 0 {
		// No row matched id+version: distinguish "gone" from "stale".
		if _, gErr := GetNode(ctx, db, n.ID); errors.Is(gErr, ErrNotFound) {
			return Node{}, ErrNotFound
		}
		return Node{}, ErrStaleVersion
	}
	n.Version++
	n.UpdatedAt = now
	return n, nil
}

// CountClientsThroughNode returns how many distinct devices route through the
// node's data plane — either with a tunnel terminating on it (a peer, i.e. the
// node is their entry) or with a cascade exit binding whose link has the node
// as entry or exit. Removal is blocked while this is non-zero, so a client's
// profile is never silently orphaned.
func CountClientsThroughNode(ctx context.Context, db *sql.DB, nodeID string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT device_id) FROM (
			SELECT device_id FROM peers WHERE node_id = ?
			UNION
			SELECT de.device_id FROM device_exits de
			  JOIN node_links nl ON de.node_link_id = nl.id
			  WHERE nl.entry_node_id = ? OR nl.exit_node_id = ?
		)`, nodeID, nodeID, nodeID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count clients through node: %w", err)
	}
	return n, nil
}

// DeleteNode removes a node. A missing row yields ErrNotFound.
func DeleteNode(ctx context.Context, db *sql.DB, id string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete node: %w", err)
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

// NextNodeConfigRevision atomically bumps and returns the next PushConfig
// revision for the node — coxswain's monotonic counter that node enforces via
// FailedPrecondition on stale values (B2). A missing node yields ErrNotFound.
func NextNodeConfigRevision(ctx context.Context, db *sql.DB, nodeID string) (int64, error) {
	var rev int64
	err := db.QueryRowContext(ctx,
		`UPDATE nodes SET config_revision = config_revision + 1
		 WHERE id = ?
		 RETURNING config_revision`, nodeID).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("next config revision: %w", err)
	}
	return rev, nil
}

// SetNodeAmneziaWG records the AmneziaWG server identity node reported for a
// node — its public key and obfuscation parameter set. coxswain calls this when it
// learns the values from a node's GetStatus; node is the source of truth, so
// the write is unconditional (no optimistic-version check) but still bumps
// version and updated_at. A missing row yields ErrNotFound.
func SetNodeAmneziaWG(ctx context.Context, db *sql.DB, nodeID, publicKey string, obf wg.Obfuscation) error {
	if !obf.IsZero() {
		if err := obf.Validate(); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	res, err := db.ExecContext(ctx,
		`UPDATE nodes SET wg_public_key = ?, wg_obfuscation = ?,
		        version = version + 1, updated_at = ?
		 WHERE id = ?`,
		publicKey, marshalObfuscation(obf), now, nodeID)
	if err != nil {
		return fmt.Errorf("set node amneziawg: %w", err)
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

func scanNode(s rowScanner) (Node, error) {
	var (
		n           Node
		endpointIPs string
		obfuscation string
	)
	err := s.Scan(&n.ID, &n.Name, &n.Region, &n.PublicIP, &endpointIPs, &n.ControlAddr,
		&n.CloudID, &n.SSHHost, &n.SSHUser, &n.SSHPort, &n.SSHHostKey,
		&n.AgentVersion, &n.WGPublicKey, &obfuscation, &n.Forwarding, &n.Masquerade, &n.Isolation,
		&n.ConfigRevision, &n.Status, &n.Version, &n.CreatedAt, &n.UpdatedAt, &n.ServerID)
	if err != nil {
		return Node{}, err
	}
	n.EndpointIPs = splitIPs(endpointIPs)
	if n.Obfuscation, err = unmarshalObfuscation(obfuscation); err != nil {
		return Node{}, err
	}
	return n, nil
}
