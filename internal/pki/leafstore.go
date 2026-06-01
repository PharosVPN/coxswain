// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// RecordNodeCert persists a signed node certificate in the `node_certs` table.
// Only the certificate is stored — coxswain never holds the node's private key. It
// returns the new record's ID.
func RecordNodeCert(ctx context.Context, db *sql.DB, nodeID string, cert SignedCert) (string, error) {
	id := idgen.New("ncrt")
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx,
		`INSERT INTO node_certs (id, node_id, serial, cert_pem, not_after, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		id, nodeID, cert.Serial, string(cert.CertPEM), cert.Cert.NotAfter, now, now)
	if err != nil {
		return "", fmt.Errorf("record node cert: %w", err)
	}
	return id, nil
}
