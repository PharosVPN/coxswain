// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package wg_test

import (
	"encoding/base64"
	"testing"

	"github.com/PharosVPN/coxswain/internal/wg"
)

func TestGenerateKeyPair(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		priv, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
		if err != nil || len(priv) != 32 {
			t.Fatalf("private key: %d bytes, err %v", len(priv), err)
		}
		pub, err := base64.StdEncoding.DecodeString(kp.PublicKey)
		if err != nil || len(pub) != 32 {
			t.Fatalf("public key: %d bytes, err %v", len(pub), err)
		}
		if kp.PrivateKey == kp.PublicKey {
			t.Fatal("private and public key are identical")
		}
		if seen[kp.PrivateKey] {
			t.Fatal("duplicate private key")
		}
		seen[kp.PrivateKey] = true
	}
}
