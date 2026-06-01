// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package pharos

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/profile"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Inspect returns a file's enc mode without decrypting it. It content-sniffs
// the fmt tag, so a renamed file still identifies (DESIGN §9).
func Inspect(data []byte) (string, error) {
	env, err := parse(data)
	if err != nil {
		return "", err
	}
	return env.Enc, nil
}

// OpenPlain decodes an enc=none file.
func OpenPlain(data []byte) (profile.Profile, error) {
	env, err := parse(data)
	if err != nil {
		return profile.Profile{}, err
	}
	if env.Enc != EncNone {
		return profile.Profile{}, ErrWrongMode
	}
	return decodeProfile(env.Payload)
}

// OpenPassword decrypts an enc=password file.
func OpenPassword(data []byte, password string) (profile.Profile, error) {
	env, err := parse(data)
	if err != nil {
		return profile.Profile{}, err
	}
	if env.Enc != EncPassword || env.KDF == nil {
		return profile.Profile{}, ErrWrongMode
	}
	aead, err := chacha20poly1305.NewX(argon2.IDKey(
		[]byte(password), env.KDF.Salt, env.KDF.Time, env.KDF.Memory, env.KDF.Threads, keySize))
	if err != nil {
		return profile.Profile{}, err
	}
	var ciphertext []byte
	if err := json.Unmarshal(env.Payload, &ciphertext); err != nil {
		return profile.Profile{}, ErrWrongPassword
	}
	aad, err := env.aad()
	if err != nil {
		return profile.Profile{}, err
	}
	plaintext, err := aead.Open(nil, env.Nonce, ciphertext, aad)
	if err != nil {
		return profile.Profile{}, ErrWrongPassword
	}
	return decodeProfile(plaintext)
}

// OpenAccount decrypts an enc=account file with the recipient's X25519 private
// key, verifying it against coxswain's profile-signing public key.
func OpenAccount(data, recipientPrivate []byte, signerPublic ed25519.PublicKey) (profile.Profile, error) {
	env, err := parse(data)
	if err != nil {
		return profile.Profile{}, err
	}
	if env.Enc != EncAccount {
		return profile.Profile{}, ErrWrongMode
	}
	var bundle e2e.SealedBundle
	if err := json.Unmarshal(env.Payload, &bundle); err != nil {
		return profile.Profile{}, fmt.Errorf("pharos: malformed account payload: %w", err)
	}
	plaintext, err := e2e.Open(bundle, recipientPrivate, signerPublic)
	if err != nil {
		return profile.Profile{}, err
	}
	return decodeProfile(plaintext)
}

func parse(data []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return envelope{}, ErrNotPharos
	}
	if env.Fmt != formatTag {
		return envelope{}, ErrNotPharos
	}
	return env, nil
}

func decodeProfile(raw []byte) (profile.Profile, error) {
	var p profile.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return profile.Profile{}, fmt.Errorf("pharos: decode profile: %w", err)
	}
	return p, nil
}
