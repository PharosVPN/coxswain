// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package e2e_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/e2e"
)

func TestPassphraseWrapRoundTrip(t *testing.T) {
	kp, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	blob, err := e2e.WrapPrivateKey("correct horse battery staple", kp.Private)
	if err != nil {
		t.Fatalf("WrapPrivateKey: %v", err)
	}
	// The wrapped blob must not contain the raw private key.
	if bytes.Contains(blob, kp.Private) {
		t.Fatal("wrapped blob leaks the plaintext private key")
	}

	got, err := e2e.UnwrapPrivateKey("correct horse battery staple", blob)
	if err != nil {
		t.Fatalf("UnwrapPrivateKey: %v", err)
	}
	if !bytes.Equal(got, kp.Private) {
		t.Error("unwrapped key does not match the original")
	}
}

func TestUnwrapWrongPassphrase(t *testing.T) {
	kp, _ := e2e.GenerateKeyPair()
	blob, _ := e2e.WrapPrivateKey("right", kp.Private)

	if _, err := e2e.UnwrapPrivateKey("wrong", blob); !errors.Is(err, e2e.ErrWrongPassphrase) {
		t.Fatalf("got %v want ErrWrongPassphrase", err)
	}
	if _, err := e2e.UnwrapPrivateKey("right", []byte("not json")); !errors.Is(err, e2e.ErrWrongPassphrase) {
		t.Fatalf("garbage blob: got %v want ErrWrongPassphrase", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	user, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signPub, signPriv, err := e2e.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	profile := []byte(`{"nodes":[],"revision":7}`)
	bundle, err := e2e.Seal(profile, user.Public, signPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(bundle.Ciphertext, profile) {
		t.Fatal("bundle ciphertext leaks plaintext")
	}

	got, err := e2e.Open(bundle, user.Private, signPub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, profile) {
		t.Errorf("opened payload mismatch: got %q", got)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	user, _ := e2e.GenerateKeyPair()
	signPub, signPriv, _ := e2e.GenerateSigningKey()

	bundle, err := e2e.Seal([]byte("secret profile"), user.Public, signPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	bundle.Ciphertext[0] ^= 0xff // flip a bit

	if _, err := e2e.Open(bundle, user.Private, signPub); !errors.Is(err, e2e.ErrBadSignature) {
		t.Fatalf("tampered bundle: got %v want ErrBadSignature", err)
	}
}

func TestOpenRejectsWrongSigner(t *testing.T) {
	user, _ := e2e.GenerateKeyPair()
	_, signPriv, _ := e2e.GenerateSigningKey()
	otherPub, _, _ := e2e.GenerateSigningKey()

	bundle, err := e2e.Seal([]byte("secret profile"), user.Public, signPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := e2e.Open(bundle, user.Private, otherPub); !errors.Is(err, e2e.ErrBadSignature) {
		t.Fatalf("wrong signer: got %v want ErrBadSignature", err)
	}
}

func TestOpenRejectsWrongRecipient(t *testing.T) {
	user, _ := e2e.GenerateKeyPair()
	intruder, _ := e2e.GenerateKeyPair()
	signPub, signPriv, _ := e2e.GenerateSigningKey()

	bundle, err := e2e.Seal([]byte("secret profile"), user.Public, signPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := e2e.Open(bundle, intruder.Private, signPub); !errors.Is(err, e2e.ErrDecrypt) {
		t.Fatalf("wrong recipient: got %v want ErrDecrypt", err)
	}
}
