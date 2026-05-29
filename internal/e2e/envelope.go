// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// wrapInfo domain-separates the key-wrap KDF.
const wrapInfo = "pharosvpn/profile/keywrap/v1"

// Envelope errors.
var (
	ErrBadSignature = errors.New("e2e: bundle signature invalid")
	ErrDecrypt      = errors.New("e2e: bundle could not be decrypted")
)

// SealedBundle is a profile encrypted to one user (DESIGN §8): the payload is
// sealed with a random data key under XChaCha20-Poly1305; the data key is
// wrapped to the user's X25519 public key via an ephemeral key; the whole
// bundle is signed by coxswain so devices can verify its origin.
type SealedBundle struct {
	V          int    `json:"v"`
	EphPublic  []byte `json:"epk"`
	WrapNonce  []byte `json:"wn"`
	WrappedKey []byte `json:"wk"`
	Nonce      []byte `json:"n"`
	Ciphertext []byte `json:"ct"`
	Signature  []byte `json:"sig"`
}

// GenerateSigningKey mints coxswain's Ed25519 profile-signing keypair.
func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Seal encrypts plaintext to recipientPublic (an X25519 public key) and signs
// the bundle with signer (coxswain's profile-signing key).
func Seal(plaintext, recipientPublic []byte, signer ed25519.PrivateKey) (SealedBundle, error) {
	dataKey := randomBytes(keySize)

	payload, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return SealedBundle{}, err
	}
	nonce := randomBytes(payload.NonceSize())
	ciphertext := payload.Seal(nil, nonce, plaintext, nil)

	// Wrap the data key to the recipient via an ephemeral X25519 key.
	ephPriv := randomBytes(keySize)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return SealedBundle{}, err
	}
	shared, err := curve25519.X25519(ephPriv, recipientPublic)
	if err != nil {
		return SealedBundle{}, fmt.Errorf("e2e: key agreement: %w", err)
	}
	wrap, err := chacha20poly1305.NewX(deriveWrapKey(shared))
	if err != nil {
		return SealedBundle{}, err
	}
	wrapNonce := randomBytes(wrap.NonceSize())

	b := SealedBundle{
		V:          1,
		EphPublic:  ephPub,
		WrapNonce:  wrapNonce,
		WrappedKey: wrap.Seal(nil, wrapNonce, dataKey, nil),
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	signed, err := b.signingBytes()
	if err != nil {
		return SealedBundle{}, err
	}
	b.Signature = ed25519.Sign(signer, signed)
	return b, nil
}

// Open verifies a bundle's signature and decrypts it with the recipient's
// X25519 private key. This is the device-side operation.
func Open(b SealedBundle, recipientPrivate []byte, signerPublic ed25519.PublicKey) ([]byte, error) {
	signed, err := b.signingBytes()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(signerPublic, signed, b.Signature) {
		return nil, ErrBadSignature
	}

	shared, err := curve25519.X25519(recipientPrivate, b.EphPublic)
	if err != nil {
		return nil, ErrDecrypt
	}
	wrap, err := chacha20poly1305.NewX(deriveWrapKey(shared))
	if err != nil {
		return nil, err
	}
	dataKey, err := wrap.Open(nil, b.WrapNonce, b.WrappedKey, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	payload, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := payload.Open(nil, b.Nonce, b.Ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// signingBytes is the deterministic byte string the signature covers — the
// bundle as JSON with the signature field cleared.
func (b SealedBundle) signingBytes() ([]byte, error) {
	unsigned := b
	unsigned.Signature = nil
	out, err := json.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("e2e: marshal bundle: %w", err)
	}
	return out, nil
}

// deriveWrapKey turns an X25519 shared secret into a 32-byte wrapping key.
func deriveWrapKey(shared []byte) []byte {
	r := hkdf.New(sha256.New, shared, nil, []byte(wrapInfo))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		panic("e2e: hkdf failed: " + err.Error())
	}
	return key
}
