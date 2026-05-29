// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package deploy_test

import (
	"context"
	"testing"

	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
)

func TestAddRelay(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	remote := newFakeRemote(t)

	res, err := deploy.AddRelay(ctx, conn, remote, bundle, deploy.RelayParams{
		Name:     "edge-1",
		Endpoint: "beacon.example.net:8444",
		Hostname: "beacon.example.net",
		SSHHost:  "203.0.113.20",
		SSHUser:  "root",
		Install:  deploy.InstallSpec{URL: "https://dl.example/beacon"},
	})
	if err != nil {
		t.Fatalf("AddRelay: %v", err)
	}

	if res.Relay.Status != fleet.StatusActive {
		t.Errorf("status: got %q want %q", res.Relay.Status, fleet.StatusActive)
	}
	if res.Relay.Kind != fleet.RelayKindRemote {
		t.Errorf("kind: got %q", res.Relay.Kind)
	}
	if res.Relay.Endpoint != "beacon.example.net:8444" {
		t.Errorf("endpoint: got %q", res.Relay.Endpoint)
	}
	if res.CertSerial == "" {
		t.Error("no cert serial reported")
	}
	if res.AgentVersion != "beacon 0.1.0-test" {
		t.Errorf("agent version: got %q", res.AgentVersion)
	}

	// The contract's three trust files plus the unit were pushed.
	for _, want := range []string{
		"/etc/beacon/relay.crt", "/etc/beacon/fleet-ca.crt",
		"/etc/beacon/device-ca.crt", "/etc/systemd/system/beacon.service",
	} {
		if _, ok := remote.uploads[want]; !ok {
			t.Errorf("expected upload of %s", want)
		}
	}

	// The relay record persisted and is listable.
	relays, err := fleet.ListRelays(ctx, conn)
	if err != nil {
		t.Fatalf("ListRelays: %v", err)
	}
	if len(relays) != 1 || relays[0].ID != res.Relay.ID {
		t.Fatalf("relay not recorded: %+v", relays)
	}
}

func TestAddRelayRequiresEndpointAndHostname(t *testing.T) {
	ctx := context.Background()
	conn := newDB(t)
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	base := deploy.RelayParams{
		Endpoint: "beacon.example.net:8444",
		Hostname: "beacon.example.net",
		SSHHost:  "203.0.113.20",
		Install:  deploy.InstallSpec{URL: "https://dl.example/beacon"},
	}
	for name, mutate := range map[string]func(*deploy.RelayParams){
		"no endpoint": func(p *deploy.RelayParams) { p.Endpoint = "" },
		"no hostname": func(p *deploy.RelayParams) { p.Hostname = "" },
		"no ssh host": func(p *deploy.RelayParams) { p.SSHHost = "" },
	} {
		p := base
		mutate(&p)
		if _, err := deploy.AddRelay(ctx, conn, newFakeRemote(t), bundle, p); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
