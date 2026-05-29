// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package e2e implements PharosVPN's end-to-end profile encryption (DESIGN
// §8): per-user X25519 keypairs, passphrase-wrapped private keys, and a signed
// hybrid envelope (XChaCha20-Poly1305 payload + X25519-wrapped data key).
//
// coxswain only ever seals — it holds users' public keys and passphrase-wrapped
// private blobs, never a usable private key. Open is the device-side operation
// and lives here as the format's executable specification.
package e2e

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Argon2id parameters for passphrase key-wrapping. Encoded in every blob.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	keySize      = 32
	saltSize     = 16
)

// ErrWrongPassphrase is returned when a passphrase-wrapped key fails to open.
var ErrWrongPassphrase = errors.New("e2e: wrong passphrase or corrupt key blob")

// KeyPair is a user's X25519 encryption keypair. coxswain keeps Public and a
// passphrase-wrapped Private; only the user's devices ever hold Private clear.
type KeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateKeyPair mints a fresh X25519 keypair for a user.
func GenerateKeyPair() (KeyPair, error) {
	priv := randomBytes(keySize)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return KeyPair{}, fmt.Errorf("e2e: derive public key: %w", err)
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

// wrappedKey is the on-disk form of a passphrase-sealed private key.
type wrappedKey struct {
	V     int    `json:"v"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"n"`
	CT    []byte `json:"ct"`
}

// WrapPrivateKey seals private under a key derived (Argon2id) from passphrase.
// The result is the opaque blob coxswain stores; coxswain never holds the passphrase.
func WrapPrivateKey(passphrase string, private []byte) ([]byte, error) {
	salt := randomBytes(saltSize)
	aead, err := chacha20poly1305.NewX(deriveKEK(passphrase, salt))
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(aead.NonceSize())
	return json.Marshal(wrappedKey{
		V:     1,
		Salt:  salt,
		Nonce: nonce,
		CT:    aead.Seal(nil, nonce, private, nil),
	})
}

// UnwrapPrivateKey recovers a private key from a WrapPrivateKey blob. A wrong
// passphrase or tampered blob yields ErrWrongPassphrase.
func UnwrapPrivateKey(passphrase string, blob []byte) ([]byte, error) {
	var wk wrappedKey
	if err := json.Unmarshal(blob, &wk); err != nil {
		return nil, ErrWrongPassphrase
	}
	aead, err := chacha20poly1305.NewX(deriveKEK(passphrase, wk.Salt))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	private, err := aead.Open(nil, wk.Nonce, wk.CT, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return private, nil
}

// deriveKEK derives a 32-byte key-encryption key from a passphrase + salt.
func deriveKEK(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keySize)
}

// randomBytes returns n cryptographically random bytes. A failing system
// random source is unrecoverable.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic("e2e: crypto/rand unavailable: " + err.Error())
	}
	return b
}
