// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package agentver

import (
	"os"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"v0.3.3":                               "v0.3.3",
		"0.3.3":                                "v0.3.3",
		"node 0.3.3":                           "v0.3.3",
		"relay v0.1.0":                         "v0.1.0",
		"v0.3.3-0.20260608014009-35a2ef86f503": "v0.3.3-0.20260608014009-35a2ef86f503",
		"":                                     "",
		"   ":                                  "",
		"not-a-version":                        "",
		"node potato":                          "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpdateAvailable(t *testing.T) {
	cases := []struct {
		name                string
		deployed, available string
		want                bool
	}{
		{"newer patch", "v0.3.2", "v0.3.3", true},
		{"newer minor", "v0.3.3", "v0.4.0", true},
		{"same", "v0.3.3", "v0.3.3", false},
		{"older available", "v0.3.3", "v0.3.2", false},
		{"prefixed forms", "node 0.3.2", "0.3.3", true},
		{"pseudo deployed, release available", "v0.3.3-0.20260608014009-35a2ef86f503", "v0.3.3", true},
		{"release deployed, pseudo available is older", "v0.3.3", "v0.3.3-0.20260608014009-35a2ef86f503", false},
		{"deployed unknown", "0.1.0-dev-not-semver!", "v0.3.3", false},
		{"available unknown", "v0.3.3", "", false},
		{"both unknown", "", "", false},
	}
	for _, c := range cases {
		if got := UpdateAvailable(c.deployed, c.available); got != c.want {
			t.Errorf("%s: UpdateAvailable(%q,%q) = %v, want %v", c.name, c.deployed, c.available, got, c.want)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := map[string]string{
		"v0.3.3":                               "v0.3.3",
		"0.3.3":                                "v0.3.3",
		"v0.3.3-0.20260608014009-35a2ef86f503": "v0.3.3-dev+35a2ef8",
		"":                                     "",
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFromFileRealBinary reads the repo's node binary if present — proves cox can
// extract a linux binary's version on any host (cross-platform, no execution).
func TestFromFileRealBinary(t *testing.T) {
	const path = "../../bin/node-linux-amd64"
	if _, err := os.Stat(path); err != nil {
		t.Skip("node binary not present; skipping real-binary version read")
	}
	v := FromFile(path)
	if v == "" {
		t.Fatal("FromFile returned empty for a real node binary")
	}
	if Normalize(v) == "" {
		t.Errorf("FromFile returned non-semver version %q", v)
	}
	t.Logf("node binary version = %s (display %s)", v, Display(v))
}
