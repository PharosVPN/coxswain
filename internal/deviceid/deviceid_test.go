// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package deviceid_test

import (
	"testing"

	"github.com/PharosVPN/coxswain/internal/deviceid"
)

func TestBundleRoundTrip(t *testing.T) {
	in := deviceid.Bundle{
		User:            "you@pharos",
		RelayAddr:       "relay.example:443",
		RelayServerName: "relay.example",
		CAFingerprint:   "ab:cd",
		FleetCAPEM:      "-----BEGIN CERTIFICATE-----\nfleet\n-----END CERTIFICATE-----\n",
		DeviceCertPEM:   "-----BEGIN CERTIFICATE-----\ndev\n-----END CERTIFICATE-----\n",
		DeviceKeyPEM:    "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
	}
	data, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := deviceid.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Fmt != deviceid.FormatTag || got.V != deviceid.FormatVersion {
		t.Fatalf("header = %s/%d", got.Fmt, got.V)
	}
	if got.RelayAddr != in.RelayAddr || got.DeviceKeyPEM != in.DeviceKeyPEM || got.User != in.User {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestParseRejectsForeignAndIncomplete(t *testing.T) {
	if _, err := deviceid.Parse([]byte(`{"fmt":"something-else","v":1}`)); err == nil {
		t.Fatal("expected rejection of a non-pharos-device file")
	}
	// Missing the private key.
	half := deviceid.Bundle{RelayAddr: "r:443", FleetCAPEM: "x", DeviceCertPEM: "y"}
	if _, err := half.Marshal(); err == nil {
		t.Fatal("expected Marshal to reject a bundle missing device_key")
	}
}
