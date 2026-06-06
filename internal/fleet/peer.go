// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package fleet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// ErrSubnetExhausted is returned when the VPN subnet has no free address.
var ErrSubnetExhausted = errors.New("fleet: VPN subnet exhausted")

// Peer binds a device to a node for one data-plane protocol (the `peers`
// table) — one end-user tunnel credential.
type Peer struct {
	ID           string
	NodeID       string
	DeviceID     string
	Protocol     string
	PublicKey    string // WG public key (AmneziaWG) or VLESS UUID (XRay/REALITY)
	AllowedIP    string
	PresharedKey string // AmneziaWG only
	// Flow is the VLESS flow for an XRay/REALITY peer (e.g. "xtls-rprx-vision");
	// empty for AmneziaWG.
	Flow      string
	Version   int
	CreatedAt time.Time
	UpdatedAt time.Time
}

const peerColumns = `id, node_id, device_id, protocol, public_key, allowed_ip,
	preshared_key, flow, version, created_at, updated_at`

// CreatePeer inserts a new peer.
func CreatePeer(ctx context.Context, db *sql.DB, p Peer) (Peer, error) {
	if p.ID == "" {
		p.ID = idgen.New("peer")
	}
	now := time.Now().UTC()
	p.Version = 1
	p.CreatedAt, p.UpdatedAt = now, now

	_, err := db.ExecContext(ctx,
		`INSERT INTO peers (`+peerColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.NodeID, p.DeviceID, p.Protocol, p.PublicKey, p.AllowedIP,
		p.PresharedKey, p.Flow, p.Version, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return Peer{}, fmt.Errorf("create peer: %w", err)
	}
	return p, nil
}

// ListPeersByDevice returns every peer for a device.
func ListPeersByDevice(ctx context.Context, db *sql.DB, deviceID string) ([]Peer, error) {
	return queryPeers(ctx, db, `WHERE device_id = ? ORDER BY created_at`, deviceID)
}

// ListPeersByNode returns every peer on a node.
func ListPeersByNode(ctx context.Context, db *sql.DB, nodeID string) ([]Peer, error) {
	return queryPeers(ctx, db, `WHERE node_id = ? ORDER BY created_at`, nodeID)
}

// DeletePeersByDevice removes every peer for a device. It returns the number
// removed.
func DeletePeersByDevice(ctx context.Context, db *sql.DB, deviceID string) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM peers WHERE device_id = ?`, deviceID)
	if err != nil {
		return 0, fmt.Errorf("delete peers: %w", err)
	}
	return res.RowsAffected()
}

// AllocateDeviceIP returns the lowest unused address in the VPN subnet. The
// network address and the first host (gateway) are reserved.
func AllocateDeviceIP(ctx context.Context, db *sql.DB, cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("fleet: bad VPN subnet %q: %w", cidr, err)
	}

	used := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT allowed_ip FROM peers`)
	if err != nil {
		return "", fmt.Errorf("fleet: read allocated IPs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", err
		}
		used[ip] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Start at network + 2 (skip the network address and the gateway).
	ip := nextIP(nextIP(append(net.IP(nil), ipnet.IP...)))
	for ipnet.Contains(ip) {
		if s := ip.String(); !used[s] {
			return s, nil
		}
		ip = nextIP(ip)
	}
	return "", ErrSubnetExhausted
}

func queryPeers(ctx context.Context, db *sql.DB, where string, args ...any) ([]Peer, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+peerColumns+` FROM peers `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.ID, &p.NodeID, &p.DeviceID, &p.Protocol, &p.PublicKey,
			&p.AllowedIP, &p.PresharedKey, &p.Flow, &p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// nextIP returns ip incremented by one, in place.
func nextIP(ip net.IP) net.IP {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip
}
