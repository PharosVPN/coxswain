// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package ssh is coxswain's SSH layer: its own outbound SSH identity and the
// client used to install and update the node agent on a node (DESIGN §5).
// SSH is a deployment channel only — all node control is gRPC.
package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"
)

// Identity is coxswain's outbound SSH credential. The operator adds AuthorizedKey
// to a new node's authorized_keys; coxswain dials out with the matching key.
type Identity struct {
	// Signer authenticates coxswain when dialing a node.
	Signer cryptossh.Signer
	// AuthorizedKey is the public key in OpenSSH authorized_keys format.
	AuthorizedKey string
}

// EnsureIdentity returns coxswain's SSH identity, generating and persisting an
// Ed25519 keypair on first call. The boolean reports whether one was created.
func EnsureIdentity(ctx context.Context, db *sql.DB) (Identity, bool, error) {
	id, err := loadIdentity(ctx, db)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Identity{}, false, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Identity{}, false, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return Identity{}, false, err
	}
	authKey := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub))) + " cox@pharosvpn"

	if _, err := db.ExecContext(ctx,
		`INSERT INTO ssh_identity (id, public_key, private_key) VALUES (1, ?, ?)`,
		authKey, string(privPEM)); err != nil {
		return Identity{}, false, fmt.Errorf("store ssh identity: %w", err)
	}

	identity, err := newIdentity(authKey, string(privPEM))
	return identity, true, err
}

func loadIdentity(ctx context.Context, db *sql.DB) (Identity, error) {
	var pub, priv string
	err := db.QueryRowContext(ctx,
		`SELECT public_key, private_key FROM ssh_identity WHERE id = 1`,
	).Scan(&pub, &priv)
	if err != nil {
		return Identity{}, err
	}
	return newIdentity(pub, priv)
}

func newIdentity(authKey, privPEM string) (Identity, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return Identity{}, errors.New("ssh identity: malformed private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Identity{}, err
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Signer: signer, AuthorizedKey: authKey}, nil
}
