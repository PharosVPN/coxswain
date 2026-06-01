// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package pharos reads and writes the `.pharos` profile file format
// (DESIGN §9): a JSON container with an always-readable header and a payload
// that is plaintext, password-encrypted, or sealed to a user account.
package pharos

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/profile"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Format constants.
const (
	formatTag     = "pharos-profile"
	formatVersion = 1

	// Extension and MIMEType identify the file to the OS and import handlers.
	Extension = ".pharos"
	MIMEType  = "application/vnd.pharosvpn.profile"
)

// Encryption modes (the `enc` header field).
const (
	EncNone     = "none"     // plaintext
	EncPassword = "password" // Argon2id + XChaCha20-Poly1305
	EncAccount  = "account"  // per-user hybrid envelope (DESIGN §8)
)

// Password-mode Argon2id parameters. Stored in every file's kdf header so they
// can evolve without breaking older files.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	keySize      = 32
	saltSize     = 16
)

// Format errors.
var (
	ErrNotPharos     = errors.New("pharos: not a pharos-profile file")
	ErrWrongMode     = errors.New("pharos: file is not in the expected enc mode")
	ErrWrongPassword = errors.New("pharos: wrong password or corrupt file")
)

// kdfParams records the password-mode key-derivation parameters.
type kdfParams struct {
	Algo    string `json:"algo"`
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
	Salt    []byte `json:"salt"`
}

// envelope is the on-disk `.pharos` container.
type envelope struct {
	Fmt     string          `json:"fmt"`
	V       int             `json:"v"`
	Enc     string          `json:"enc"`
	KDF     *kdfParams      `json:"kdf,omitempty"`
	Nonce   []byte          `json:"nonce,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// aad returns the authenticated header bytes — the envelope with the payload
// cleared. Feeding it as AEAD additional data authenticates enc/v/KDF params,
// so a file's mode or KDF cannot be downgraded (DESIGN §9).
func (e envelope) aad() ([]byte, error) {
	h := e
	h.Payload = nil
	return json.Marshal(h)
}

// WritePlain renders an unencrypted `.pharos` file.
func WritePlain(p profile.Profile) ([]byte, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("pharos: marshal profile: %w", err)
	}
	return json.MarshalIndent(envelope{
		Fmt: formatTag, V: formatVersion, Enc: EncNone, Payload: payload,
	}, "", "  ")
}

// WritePassword renders a password-encrypted `.pharos` file.
func WritePassword(p profile.Profile, password string) ([]byte, error) {
	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("pharos: marshal profile: %w", err)
	}
	salt := randomBytes(saltSize)
	kdf := &kdfParams{
		Algo: "argon2id", Time: argonTime, Memory: argonMemory,
		Threads: argonThreads, Salt: salt,
	}
	aead, err := chacha20poly1305.NewX(
		argon2.IDKey([]byte(password), salt, kdf.Time, kdf.Memory, kdf.Threads, keySize))
	if err != nil {
		return nil, err
	}
	env := envelope{
		Fmt: formatTag, V: formatVersion, Enc: EncPassword,
		KDF: kdf, Nonce: randomBytes(aead.NonceSize()),
	}
	aad, err := env.aad()
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, env.Nonce, plaintext, aad)
	if env.Payload, err = json.Marshal(ciphertext); err != nil {
		return nil, err
	}
	return json.MarshalIndent(env, "", "  ")
}

// WriteAccount renders an account-encrypted `.pharos` file: the profile is
// sealed to recipientPublic (an X25519 key) and signed by signer (coxswain's
// profile-signing key). The payload is an e2e sealed bundle (DESIGN §8).
func WriteAccount(p profile.Profile, recipientPublic []byte, signer ed25519.PrivateKey) ([]byte, error) {
	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("pharos: marshal profile: %w", err)
	}
	bundle, err := e2e.Seal(plaintext, recipientPublic, signer)
	if err != nil {
		return nil, err
	}
	return WrapSealedBundle(bundle)
}

// WrapSealedBundle renders an account-mode `.pharos` file around an
// already-sealed bundle. coxswain stores only ciphertext, so this is how it
// exports a stored profile — no re-sealing, no plaintext.
func WrapSealedBundle(bundle e2e.SealedBundle) ([]byte, error) {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(envelope{
		Fmt: formatTag, V: formatVersion, Enc: EncAccount, Payload: payload,
	}, "", "  ")
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("pharos: crypto/rand unavailable: " + err.Error())
	}
	return b
}
