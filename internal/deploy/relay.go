// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package deploy

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/idgen"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// On-host layout and the coxswain↔beacon CLI contract for relay enrollment
// (BUILD.md "Relay enrollment contract"). It mirrors the buoy contract above.
const (
	beaconBinaryPath = "/usr/local/bin/beacon"
	relayCertPath    = "/etc/beacon/relay.crt"
	fleetCAPath      = "/etc/beacon/fleet-ca.crt"
	deviceCAPath     = "/etc/beacon/device-ca.crt"
	beaconUnitPath   = "/etc/systemd/system/beacon.service"
	// beaconEgressUnitPath is the control-plane egress relay's unit (decision 19),
	// a second beacon process alongside the ingress one. Staged only when the
	// relay is enrolled with an egress endpoint.
	beaconEgressUnitPath = "/etc/systemd/system/beacon-egress.service"

	// cmdRelayGenCSR makes beacon generate its keypair on the host and print
	// a plain CSR; coxswain overrides the identity when it signs (SignRelayCSR).
	cmdRelayGenCSR = beaconBinaryPath + " gen-csr"
	// cmdRelayVersion prints the installed beacon version.
	cmdRelayVersion = beaconBinaryPath + " version"
	// cmdRelayOnionKey makes beacon mint/print its X25519 onion public key
	// (decision 20); the private key stays on the host.
	cmdRelayOnionKey = beaconBinaryPath + " onion-key"
	// beaconOnionUnitPath is the onion relay's systemd unit, a third beacon
	// process. Staged only when the relay is enrolled with an onion endpoint.
	beaconOnionUnitPath = "/etc/systemd/system/beacon-onion.service"
)

const beaconUnit = `[Unit]
Description=PharosVPN beacon relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + beaconBinaryPath + ` run --config-dir /etc/beacon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// beaconEgressUnit is the systemd unit for the control-plane egress relay
// (decision 19): a second beacon process listening for coxswain's egress tunnel
// on tunnelAddr (e.g. ":8456"). It reuses the same /etc/beacon material.
func beaconEgressUnit(tunnelAddr string) string {
	return `[Unit]
Description=PharosVPN beacon control-plane egress relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + beaconBinaryPath + ` egress --tunnel-addr ` + tunnelAddr + ` --config-dir /etc/beacon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// beaconOnionUnit is the systemd unit for the control-plane onion relay
// (decision 20): a beacon process peeling onion layers on listenAddr (":8457").
func beaconOnionUnit(listenAddr string) string {
	return `[Unit]
Description=PharosVPN beacon control-plane onion relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + beaconBinaryPath + ` onion --listen ` + listenAddr + ` --config-dir /etc/beacon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`
}

// RelayParams are the inputs to AddRelay.
type RelayParams struct {
	Name string // generated if empty
	// Region locates the relay on the admin map (a DigitalOcean/cloud region
	// code). Optional.
	Region string
	// Endpoint is the reverse-tunnel address coxswain will dial — stored on the
	// relay record and used by `cox serve`. Required.
	Endpoint string
	// Hostname is the relay's public client endpoint; coxswain signs it into the
	// relay cert as a SAN so caravel can verify the relay. Required.
	Hostname string
	// EgressEndpoint, when set, also enrols this relay as coxswain's control-plane
	// egress hop (decision 19): coxswain dials it to reach nodes. It must use the
	// relay's signed hostname so the tunnel TLS verifies. Empty = no egress.
	EgressEndpoint string
	// EgressHop is this relay's 1-based position in the egress chain (ignored
	// when EgressEndpoint is empty).
	EgressHop int
	// OnionEndpoint, when set, also enrols this relay as an onion hop (decision
	// 20): it stages `beacon onion` on this address and records the relay's onion
	// public key. Reuses EgressHop for ordering; empty = no onion.
	OnionEndpoint string
	// NoIngress skips the client-facing ingress beacon (`beacon run`), staging
	// only the egress/onion roles. This lets a relay share a host with a buoy
	// node without both fighting for the same port — the individual's "one box,
	// many roles". Requires an egress or onion endpoint.
	NoIngress bool
	SSHHost   string // required
	SSHUser        string
	SSHPort        int
	Install        InstallSpec
}

// RelayResult reports what relay enrollment produced.
type RelayResult struct {
	Relay        fleet.Relay
	CertSerial   string
	AgentVersion string
}

// AddRelay installs the beacon binary on an already-connected host, signs its
// relay certificate off the Fleet CA, pushes the trust material, and starts
// the service (BUILD.md "Relay enrollment contract"). On failure the relay
// record is left with status "error".
func AddRelay(ctx context.Context, db *sql.DB, remote Remote, bundle pki.Bundle, p RelayParams) (RelayResult, error) {
	switch {
	case p.Endpoint == "" && !p.NoIngress:
		return RelayResult{}, fmt.Errorf("deploy: relay tunnel endpoint is required")
	case p.NoIngress && p.EgressEndpoint == "" && p.OnionEndpoint == "":
		return RelayResult{}, fmt.Errorf("deploy: a no-ingress relay needs --egress or --onion")
	case p.Hostname == "":
		return RelayResult{}, fmt.Errorf("deploy: relay hostname is required")
	case p.SSHHost == "":
		return RelayResult{}, fmt.Errorf("deploy: ssh host is required")
	}
	if err := p.Install.validate(); err != nil {
		return RelayResult{}, err
	}

	name := p.Name
	if name == "" {
		name = generateRelayName()
	}

	relay, err := fleet.CreateRelay(ctx, db, fleet.Relay{
		Name:           name,
		Kind:           fleet.RelayKindRemote,
		Region:         p.Region,
		Endpoint:       p.Endpoint,
		EgressEndpoint: p.EgressEndpoint,
		EgressHop:      p.EgressHop,
		OnionEndpoint:  p.OnionEndpoint,
		Status:         fleet.StatusProvisioning,
	})
	if err != nil {
		return RelayResult{}, err
	}

	res, err := enrolRelay(ctx, db, remote, bundle, &relay, p)
	if err != nil {
		relay.Status = fleet.StatusError
		_, _ = fleet.UpdateRelay(ctx, db, relay)
		return RelayResult{}, err
	}
	return res, nil
}

// enrolRelay runs the install/sign/start sequence against an existing relay
// record.
func enrolRelay(ctx context.Context, db *sql.DB, remote Remote, bundle pki.Bundle, relay *fleet.Relay, p RelayParams) (RelayResult, error) {
	if err := installBinary(ctx, remote, p.Install, beaconBinaryPath); err != nil {
		return RelayResult{}, err
	}

	// beacon generates its keypair on the host and returns a plain CSR; the
	// relay private key never crosses to coxswain.
	csrPEM, err := remote.Run(ctx, cmdRelayGenCSR, nil)
	if err != nil {
		return RelayResult{}, fmt.Errorf("deploy: beacon gen-csr: %w", err)
	}
	signed, err := pki.SignRelayCSR(bundle.Fleet, csrPEM, p.Hostname)
	if err != nil {
		return RelayResult{}, err
	}

	// relay.crt carries the leaf plus the Fleet intermediate so beacon can
	// present a full chain to caravel; the two CA files are the trust roots
	// for the client and backend legs.
	relayChain := append(append([]byte{}, signed.CertPEM...), bundle.Fleet.CertPEM...)
	for _, f := range []struct {
		path string
		data []byte
	}{
		{relayCertPath, relayChain},
		{fleetCAPath, bundle.Fleet.CertPEM},
		{deviceCAPath, bundle.Device.CertPEM},
	} {
		if err := remote.Upload(ctx, f.path, f.data, 0o644); err != nil {
			return RelayResult{}, err
		}
	}

	// The client-facing ingress beacon — skipped on a co-located relay so it does
	// not contend for the buoy's port (the "one box, many roles" case).
	if !p.NoIngress {
		if err := remote.Upload(ctx, beaconUnitPath, []byte(beaconUnit), 0o644); err != nil {
			return RelayResult{}, err
		}
		if _, err := remote.Run(ctx, "systemctl daemon-reload && systemctl enable --now beacon", nil); err != nil {
			return RelayResult{}, fmt.Errorf("deploy: start beacon service: %w", err)
		}
	}

	// Control-plane egress relay (decision 19): a second beacon process. The
	// relay listens on the egress endpoint's port; coxswain dials the hostname.
	if p.EgressEndpoint != "" {
		_, port, err := net.SplitHostPort(p.EgressEndpoint)
		if err != nil {
			return RelayResult{}, fmt.Errorf("deploy: egress endpoint %q: %w", p.EgressEndpoint, err)
		}
		if err := remote.Upload(ctx, beaconEgressUnitPath, []byte(beaconEgressUnit(":"+port)), 0o644); err != nil {
			return RelayResult{}, err
		}
		if _, err := remote.Run(ctx, "systemctl daemon-reload && systemctl enable --now beacon-egress", nil); err != nil {
			return RelayResult{}, fmt.Errorf("deploy: start beacon-egress service: %w", err)
		}
	}

	// Onion hop (decision 20): mint the relay's onion key, record its public
	// half, and run `beacon onion` alongside.
	if p.OnionEndpoint != "" {
		out, err := remote.Run(ctx, cmdRelayOnionKey, nil)
		if err != nil {
			return RelayResult{}, fmt.Errorf("deploy: beacon onion-key: %w", err)
		}
		relay.OnionPubKey = strings.TrimSpace(string(out))
		_, port, err := net.SplitHostPort(p.OnionEndpoint)
		if err != nil {
			return RelayResult{}, fmt.Errorf("deploy: onion endpoint %q: %w", p.OnionEndpoint, err)
		}
		if err := remote.Upload(ctx, beaconOnionUnitPath, []byte(beaconOnionUnit(":"+port)), 0o644); err != nil {
			return RelayResult{}, err
		}
		if _, err := remote.Run(ctx, "systemctl daemon-reload && systemctl enable --now beacon-onion", nil); err != nil {
			return RelayResult{}, fmt.Errorf("deploy: start beacon-onion service: %w", err)
		}
		relay.OnionEndpoint = p.OnionEndpoint
	}

	agentVersion := readVersion(ctx, remote, cmdRelayVersion)

	relay.Status = fleet.StatusActive
	updated, err := fleet.UpdateRelay(ctx, db, *relay)
	if err != nil {
		return RelayResult{}, err
	}
	return RelayResult{Relay: updated, CertSerial: signed.Serial, AgentVersion: agentVersion}, nil
}

func generateRelayName() string {
	suffix := idgen.New("r")
	if len(suffix) > 6 {
		suffix = suffix[len(suffix)-6:]
	}
	return "relay-" + suffix
}
