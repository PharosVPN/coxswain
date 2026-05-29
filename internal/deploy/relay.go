// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package deploy

import (
	"context"
	"database/sql"
	"fmt"

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

	// cmdRelayGenCSR makes beacon generate its keypair on the host and print
	// a plain CSR; coxswain overrides the identity when it signs (SignRelayCSR).
	cmdRelayGenCSR = beaconBinaryPath + " gen-csr"
	// cmdRelayVersion prints the installed beacon version.
	cmdRelayVersion = beaconBinaryPath + " version"
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

// RelayParams are the inputs to AddRelay.
type RelayParams struct {
	Name string // generated if empty
	// Endpoint is the reverse-tunnel address coxswain will dial — stored on the
	// relay record and used by `cox serve`. Required.
	Endpoint string
	// Hostname is the relay's public client endpoint; coxswain signs it into the
	// relay cert as a SAN so caravel can verify the relay. Required.
	Hostname string
	SSHHost  string // required
	SSHUser  string
	SSHPort  int
	Install  InstallSpec
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
	case p.Endpoint == "":
		return RelayResult{}, fmt.Errorf("deploy: relay tunnel endpoint is required")
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
		Name:     name,
		Kind:     fleet.RelayKindRemote,
		Endpoint: p.Endpoint,
		Status:   fleet.StatusProvisioning,
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

	if err := remote.Upload(ctx, beaconUnitPath, []byte(beaconUnit), 0o644); err != nil {
		return RelayResult{}, err
	}
	if _, err := remote.Run(ctx, "systemctl daemon-reload && systemctl enable --now beacon", nil); err != nil {
		return RelayResult{}, fmt.Errorf("deploy: start beacon service: %w", err)
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
