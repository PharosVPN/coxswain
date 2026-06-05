// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package deviceid is the caravel device-identity bundle (`.pharosid`) — the
// mTLS client leaf a device presents to a relay to reach AccountSync, plus how
// to find and verify that relay. It is the offline (manual-bundle) counterpart
// of the enrollment-ticket QR: `cox devices issue` writes one, the operator
// copies it to the device, and caravel imports it. The account passphrase is
// NOT in the bundle — it authenticates separately at AccountSync.Authenticate.
package deviceid

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Format constants — must match caravel's parser.
const (
	FormatTag     = "pharos-device"
	FormatVersion = 1
	// Extension identifies the bundle to the OS / import handlers.
	Extension = ".pharosid"
)

// Bundle is a device's relayed-sync identity. The device dials RelayAddr with
// its DeviceCert leaf (RootCAs = FleetCA, ServerName = RelayServerName), then
// speaks AccountSync over that mTLS channel.
type Bundle struct {
	Fmt string `json:"fmt"`
	V   int    `json:"v"`
	// User pre-fills the account login on the device (convenience, not a secret).
	User string `json:"user,omitempty"`
	// RelayAddr is the host:port caravel dials.
	RelayAddr string `json:"relay_addr"`
	// RelayServerName is the SAN to verify the relay's leaf against (its
	// hostname/IP, or "localhost"/127.0.0.1 for an embedded relay).
	RelayServerName string `json:"relay_server_name"`
	// CAFingerprint pins the root CA (matches the ticket QR's `ca` field).
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
	// FleetCAPEM is the trust root that verifies the relay's server cert.
	FleetCAPEM string `json:"fleet_ca"`
	// DeviceCertPEM / DeviceKeyPEM are the device's mTLS client leaf and key.
	DeviceCertPEM string `json:"device_cert"`
	DeviceKeyPEM  string `json:"device_key"`
}

// Marshal renders the bundle as indented JSON for a `.pharosid` file.
func (b Bundle) Marshal() ([]byte, error) {
	b.Fmt = FormatTag
	b.V = FormatVersion
	if err := b.validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(b, "", "  ")
}

// Parse decodes and validates a `.pharosid` file.
func Parse(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("deviceid: %w", err)
	}
	if b.Fmt != FormatTag {
		return Bundle{}, errors.New("deviceid: not a pharos-device bundle")
	}
	if b.V != FormatVersion {
		return Bundle{}, fmt.Errorf("deviceid: unsupported version %d", b.V)
	}
	if err := b.validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func (b Bundle) validate() error {
	switch {
	case b.RelayAddr == "":
		return errors.New("deviceid: missing relay_addr")
	case b.FleetCAPEM == "":
		return errors.New("deviceid: missing fleet_ca")
	case b.DeviceCertPEM == "":
		return errors.New("deviceid: missing device_cert")
	case b.DeviceKeyPEM == "":
		return errors.New("deviceid: missing device_key")
	}
	return nil
}
