// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile_test

import (
	"encoding/json"
	"testing"

	"github.com/PharosVPN/coxswain/internal/profile"
)

// TestBuildEmitsPath checks that a path-bound device's profile carries the
// ordered egress chain (entry → mid → exit) and that a single-node device omits
// it entirely (the `path` key is absent, not null).
func TestBuildEmitsPath(t *testing.T) {
	in := profile.BuildInput{
		User:        "usr_1",
		DeviceWGKey: "priv",
		TunnelIP:    "10.8.0.2",
		Nodes: []profile.BuildNode{
			{ID: "nod_entry", Name: "nyc", Region: "nyc1", EndpointIPs: []string{"1.1.1.1"}, WGPublicKey: "pub"},
		},
		Path: &profile.PathView{
			Name: "fast-eu",
			Hops: []profile.PathHop{
				{ID: "nod_entry", Name: "nyc", Region: "nyc1", Role: "entry", IPs: []string{"1.1.1.1"}},
				{ID: "nod_mid", Name: "lon", Region: "lon1", Role: "mid", IPs: []string{"2.2.2.2"}},
				{ID: "nod_exit", Name: "ams", Region: "ams3", Role: "exit", IPs: []string{"3.3.3.3"}},
			},
		},
	}

	p := profile.Build(in)
	if p.Path == nil {
		t.Fatal("Build dropped the path")
	}
	if p.Path.Name != "fast-eu" || len(p.Path.Hops) != 3 {
		t.Fatalf("path = %+v, want fast-eu with 3 hops", p.Path)
	}
	if p.Path.Hops[0].Role != "entry" || p.Path.Hops[2].Role != "exit" {
		t.Fatalf("roles = %s..%s, want entry..exit", p.Path.Hops[0].Role, p.Path.Hops[2].Role)
	}
	// The entry hop's node id must be a Node the client can dial.
	if p.Path.Hops[0].ID != p.Nodes[0].ID {
		t.Fatalf("entry id %s not in Nodes", p.Path.Hops[0].ID)
	}

	// A single-node device omits the key (so old clients see no `path`).
	in.Path = nil
	out, err := json.Marshal(profile.Build(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); contains(got, `"path"`) {
		t.Fatalf("single-node profile should omit path, got %s", got)
	}
}

// TestBuildEmitsBothProtocols checks that a node reporting both data-plane
// identities yields a Node with two protocol entries (AmneziaWG + XRay/REALITY),
// each carrying the right server key, port, and the device's per-protocol
// identity; and that a node missing the XRay key emits only AmneziaWG.
func TestBuildEmitsBothProtocols(t *testing.T) {
	in := profile.BuildInput{
		User:           "usr_1",
		DeviceWGKey:    "wg-priv",
		DeviceXRayUUID: "uuid-1234",
		TunnelIP:       "10.8.0.7",
		Nodes: []profile.BuildNode{
			{ID: "nod_a", Name: "nyc", Region: "nyc1", EndpointIPs: []string{"1.1.1.1"},
				WGPublicKey: "wg-pub", XRayPublicKey: "reality-pub", AllowedIPs: []string{"0.0.0.0/0"}},
			{ID: "nod_b", Name: "lon", Region: "lon1", EndpointIPs: []string{"2.2.2.2"},
				WGPublicKey: "wg-pub-2"}, // no REALITY key reported
		},
		XRay: profile.XRayClientPolicy{
			ServerName: "www.microsoft.com", ShortID: "", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
		},
	}

	p := profile.Build(in)
	if len(p.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(p.Nodes))
	}

	// nod_a offers both protocols.
	if got := len(p.Nodes[0].Protocols); got != 2 {
		t.Fatalf("nod_a protocols = %d, want 2", got)
	}
	byType := map[string]profile.Protocol{}
	for _, pr := range p.Nodes[0].Protocols {
		byType[pr.Type] = pr
	}
	if _, ok := byType[profile.ProtocolAmneziaWG]; !ok {
		t.Fatal("nod_a missing amneziawg entry")
	}
	xray, ok := byType[profile.ProtocolXRayReality]
	if !ok {
		t.Fatal("nod_a missing xray-reality entry")
	}
	var xp struct {
		UUID       string `json:"uuid"`
		Flow       string `json:"flow"`
		PublicKey  string `json:"public_key"`
		ServerName string `json:"server_name"`
		Endpoints  []struct {
			IP      string `json:"ip"`
			PortMin int    `json:"port_min"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(xray.Params, &xp); err != nil {
		t.Fatalf("decode xray params: %v", err)
	}
	if xp.UUID != "uuid-1234" || xp.Flow != "xtls-rprx-vision" || xp.PublicKey != "reality-pub" {
		t.Fatalf("xray params = %+v, want uuid-1234 / vision / reality-pub", xp)
	}
	if xp.ServerName != "www.microsoft.com" {
		t.Fatalf("xray server_name = %q, want www.microsoft.com", xp.ServerName)
	}
	if len(xp.Endpoints) != 1 || xp.Endpoints[0].PortMin != profile.XRayListenPort {
		t.Fatalf("xray endpoints = %+v, want one on port %d", xp.Endpoints, profile.XRayListenPort)
	}

	// nod_b reported no REALITY key → AmneziaWG only.
	if got := len(p.Nodes[1].Protocols); got != 1 || p.Nodes[1].Protocols[0].Type != profile.ProtocolAmneziaWG {
		t.Fatalf("nod_b protocols = %+v, want amneziawg only", p.Nodes[1].Protocols)
	}
}

// TestRealityCamouflage covers the decoy → dest/serverNames derivation that
// both the node config and the client profile rely on.
func TestRealityCamouflage(t *testing.T) {
	dest, names := profile.RealityCamouflage("www.microsoft.com")
	if dest != "www.microsoft.com:443" || len(names) != 1 || names[0] != "www.microsoft.com" {
		t.Fatalf("bare host: dest=%q names=%v", dest, names)
	}
	dest, names = profile.RealityCamouflage("example.com:8443")
	if dest != "example.com:8443" || names[0] != "example.com" {
		t.Fatalf("host:port: dest=%q names=%v", dest, names)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
