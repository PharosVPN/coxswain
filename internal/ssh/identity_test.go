// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package ssh_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/ssh"
)

func TestEnsureIdentity(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	ctx := context.Background()

	first, created, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		t.Fatalf("first EnsureIdentity: %v", err)
	}
	if !created {
		t.Error("first EnsureIdentity: expected created=true")
	}
	if first.Signer == nil {
		t.Fatal("identity has no signer")
	}
	if !strings.HasPrefix(first.AuthorizedKey, "ssh-ed25519 ") {
		t.Errorf("authorized key not an ed25519 key: %q", first.AuthorizedKey)
	}

	second, created, err := ssh.EnsureIdentity(ctx, conn)
	if err != nil {
		t.Fatalf("second EnsureIdentity: %v", err)
	}
	if created {
		t.Error("second EnsureIdentity: expected created=false")
	}
	if first.AuthorizedKey != second.AuthorizedKey {
		t.Error("identity changed across calls")
	}
}
