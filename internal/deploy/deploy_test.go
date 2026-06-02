// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package deploy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// fakeRemote stands in for an SSH connection to a node.
type fakeRemote struct {
	csrPEM   []byte
	hostKey  string
	uploads  map[string][]byte
	commands []string
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node"}}, key)
	if err != nil {
		t.Fatalf("node CSR: %v", err)
	}
	return &fakeRemote{
		csrPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		hostKey: "ssh-ed25519 AAAAC3Nzdummyhostkey node",
		uploads: map[string][]byte{},
	}
}

func (f *fakeRemote) Run(_ context.Context, cmd string, _ []byte) ([]byte, error) {
	f.commands = append(f.commands, cmd)
	switch cmd {
	case "/usr/local/bin/node gen-csr":
		return f.csrPEM, nil
	case "/usr/local/bin/node version":
		return []byte("node 0.1.0-test\n"), nil
	case "/usr/local/bin/relay gen-csr":
		return f.csrPEM, nil
	case "/usr/local/bin/relay version":
		return []byte("relay 0.1.0-test\n"), nil
	default:
		return nil, nil
	}
}

func (f *fakeRemote) Upload(_ context.Context, path string, data []byte, _ fs.FileMode) error {
	f.uploads[path] = data
	return nil
}

func (f *fakeRemote) HostKey() string { return f.hostKey }
func (f *fakeRemote) Close() error    { return nil }

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return conn
}

func TestAddNode(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	remote := newFakeRemote(t)

	res, err := deploy.AddNode(ctx, conn, remote, bundle, deploy.AddParams{
		Region:  "ams",
		SSHHost: "203.0.113.10",
		SSHUser: "root",
		Install: deploy.InstallSpec{URL: "https://dl.example/node"},
	})
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	if res.Node.Status != fleet.StatusActive {
		t.Errorf("status: got %q want %q", res.Node.Status, fleet.StatusActive)
	}
	if res.Node.SSHHostKey != remote.hostKey {
		t.Errorf("host key not pinned: got %q", res.Node.SSHHostKey)
	}
	if res.NodeCertID == "" {
		t.Error("no node cert recorded")
	}
	if res.AgentVersion != "node 0.1.0-test" {
		t.Errorf("agent version: got %q", res.AgentVersion)
	}
	for _, want := range []string{
		"/etc/node/node.crt", "/etc/node/ca.crt", "/etc/systemd/system/node.service",
	} {
		if _, ok := remote.uploads[want]; !ok {
			t.Errorf("expected upload of %s", want)
		}
	}

	// The signed cert really chains to the CA.
	got, err := fleet.GetNode(ctx, conn, res.Node.ID)
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if got.ControlAddr != "203.0.113.10:8444" {
		t.Errorf("control addr: got %q", got.ControlAddr)
	}
}

func TestAddNodeUploadsBinary(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	remote := newFakeRemote(t)

	binary := []byte("\x7fELF fake node binary")
	if _, err := deploy.AddNode(ctx, conn, remote, bundle, deploy.AddParams{
		Region:  "fra",
		SSHHost: "node.example.com",
		Install: deploy.InstallSpec{Binary: binary},
	}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if got := remote.uploads["/usr/local/bin/node"]; string(got) != string(binary) {
		t.Error("node binary was not uploaded")
	}
}

func TestInstallSpecValidation(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	for name, spec := range map[string]deploy.InstallSpec{
		"neither": {},
		"both":    {Binary: []byte("x"), URL: "https://example/node"},
	} {
		_, err := deploy.AddNode(ctx, conn, newFakeRemote(t), bundle, deploy.AddParams{
			Region: "ams", SSHHost: "203.0.113.1", Install: spec,
		})
		if err == nil {
			t.Errorf("%s install spec: expected error", name)
		}
	}
}

func TestServiceUnknownAction(t *testing.T) {
	if err := deploy.Service(context.Background(), newFakeRemote(t), "bounce"); err == nil {
		t.Error("expected error for unknown service action")
	}
}
