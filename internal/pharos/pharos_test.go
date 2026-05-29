// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package pharos_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/pharos"
	"github.com/PharosVPN/coxswain/internal/profile"
)

func sampleProfile() profile.Profile {
	return profile.Profile{
		FleetID:  "fleet-1",
		User:     "usr_abc",
		Revision: 3,
		Nodes: []profile.Node{
			{ID: "nod_a", Name: "ams-1", Region: "eu", Endpoints: []string{"203.0.113.7:443"}},
		},
	}
}

func TestPlainRoundTrip(t *testing.T) {
	file, err := pharos.WritePlain(sampleProfile())
	if err != nil {
		t.Fatalf("WritePlain: %v", err)
	}
	if enc, _ := pharos.Inspect(file); enc != pharos.EncNone {
		t.Errorf("Inspect: got %q want none", enc)
	}
	got, err := pharos.OpenPlain(file)
	if err != nil {
		t.Fatalf("OpenPlain: %v", err)
	}
	if got.FleetID != "fleet-1" || got.Revision != 3 || len(got.Nodes) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	file, err := pharos.WritePassword(sampleProfile(), "a-good-password")
	if err != nil {
		t.Fatalf("WritePassword: %v", err)
	}
	if enc, _ := pharos.Inspect(file); enc != pharos.EncPassword {
		t.Errorf("Inspect: got %q want password", enc)
	}
	if bytes.Contains(file, []byte("nod_a")) {
		t.Fatal("password file leaks plaintext")
	}

	got, err := pharos.OpenPassword(file, "a-good-password")
	if err != nil {
		t.Fatalf("OpenPassword: %v", err)
	}
	if got.User != "usr_abc" || len(got.Nodes) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	if _, err := pharos.OpenPassword(file, "wrong"); !errors.Is(err, pharos.ErrWrongPassword) {
		t.Errorf("wrong password: got %v want ErrWrongPassword", err)
	}
}

func TestPasswordRejectsKDFDowngrade(t *testing.T) {
	file, err := pharos.WritePassword(sampleProfile(), "pw")
	if err != nil {
		t.Fatalf("WritePassword: %v", err)
	}
	// Tamper with the header (the kdf params are AEAD additional data).
	tampered := bytes.Replace(file, []byte(`"m": 65536`), []byte(`"m": 8`), 1)
	if bytes.Equal(tampered, file) {
		t.Skip("header layout changed; update the tamper target")
	}
	if _, err := pharos.OpenPassword(tampered, "pw"); !errors.Is(err, pharos.ErrWrongPassword) {
		t.Errorf("KDF downgrade: got %v want ErrWrongPassword", err)
	}
}

func TestAccountRoundTrip(t *testing.T) {
	user, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signPub, signPriv, err := e2e.GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}

	file, err := pharos.WriteAccount(sampleProfile(), user.Public, signPriv)
	if err != nil {
		t.Fatalf("WriteAccount: %v", err)
	}
	if enc, _ := pharos.Inspect(file); enc != pharos.EncAccount {
		t.Errorf("Inspect: got %q want account", enc)
	}
	if bytes.Contains(file, []byte("nod_a")) {
		t.Fatal("account file leaks plaintext")
	}

	got, err := pharos.OpenAccount(file, user.Private, signPub)
	if err != nil {
		t.Fatalf("OpenAccount: %v", err)
	}
	if got.FleetID != "fleet-1" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	intruder, _ := e2e.GenerateKeyPair()
	if _, err := pharos.OpenAccount(file, intruder.Private, signPub); err == nil {
		t.Error("OpenAccount accepted the wrong recipient key")
	}
}

func TestInspectAndModeGuards(t *testing.T) {
	if _, err := pharos.Inspect([]byte(`{"fmt":"something-else"}`)); !errors.Is(err, pharos.ErrNotPharos) {
		t.Errorf("non-pharos: got %v want ErrNotPharos", err)
	}
	if _, err := pharos.Inspect([]byte("not json")); !errors.Is(err, pharos.ErrNotPharos) {
		t.Errorf("garbage: got %v want ErrNotPharos", err)
	}

	plain, _ := pharos.WritePlain(sampleProfile())
	if _, err := pharos.OpenPassword(plain, "pw"); !errors.Is(err, pharos.ErrWrongMode) {
		t.Errorf("mode guard: got %v want ErrWrongMode", err)
	}
}
