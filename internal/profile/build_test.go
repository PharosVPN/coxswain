// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package profile_test

import (
	"encoding/json"
	"testing"

	"github.com/PharosVPN/coxswain/internal/profile"
)

// TestBuildEmitsPath checks that a cascade profile carries the ordered egress
// chain (entry → mid → exit), that only the entry hop is emitted as a dialable
// node, and that a direct profile omits the chain entirely (the `path` key is
// absent, not null).
func TestBuildEmitsPath(t *testing.T) {
	in := profile.BuildInput{
		SpecID:      "pspec_1",
		Name:        "EU Cascade",
		Protocol:    profile.ProtocolAmneziaWG,
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

	cp := profile.BuildClientProfile(in)
	if cp.ID != "pspec_1" || cp.Name != "EU Cascade" || cp.Protocol != profile.ProtocolAmneziaWG {
		t.Fatalf("client profile metadata = %+v", cp)
	}
	if cp.Path == nil {
		t.Fatal("BuildClientProfile dropped the path")
	}
	if cp.Path.Name != "fast-eu" || len(cp.Path.Hops) != 3 {
		t.Fatalf("path = %+v, want fast-eu with 3 hops", cp.Path)
	}
	if cp.Path.Hops[0].Role != "entry" || cp.Path.Hops[2].Role != "exit" {
		t.Fatalf("roles = %s..%s, want entry..exit", cp.Path.Hops[0].Role, cp.Path.Hops[2].Role)
	}
	// The entry hop's node id must be the one dialable Node.
	if len(cp.Nodes) != 1 || cp.Path.Hops[0].ID != cp.Nodes[0].ID {
		t.Fatalf("entry id %s not the sole dialable node %+v", cp.Path.Hops[0].ID, cp.Nodes)
	}

	// A direct profile omits the key (so clients see no `path`).
	in.Path = nil
	out, err := json.Marshal(profile.BuildClientProfile(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(out); contains(got, `"path"`) {
		t.Fatalf("direct profile should omit path, got %s", got)
	}
}

// TestBuildEmitsRequestedProtocol checks that BuildClientProfile emits only the
// profile's single protocol: an XRay profile carries XRay entries (with the
// right key/port/identity) and drops nodes missing a REALITY key; an AmneziaWG
// profile over the same nodes keeps both.
func TestBuildEmitsRequestedProtocol(t *testing.T) {
	nodes := []profile.BuildNode{
		{ID: "nod_a", Name: "nyc", Region: "nyc1", EndpointIPs: []string{"1.1.1.1"},
			WGPublicKey: "wg-pub", XRayPublicKey: "reality-pub", AllowedIPs: []string{"0.0.0.0/0"}},
		{ID: "nod_b", Name: "lon", Region: "lon1", EndpointIPs: []string{"2.2.2.2"},
			WGPublicKey: "wg-pub-2"}, // no REALITY key reported
	}

	// XRay profile: only nod_a qualifies (nod_b has no REALITY key).
	xrayCP := profile.BuildClientProfile(profile.BuildInput{
		SpecID:         "pspec_xray",
		Name:           "Stealth",
		Protocol:       profile.ProtocolXRayReality,
		DeviceXRayUUID: "uuid-1234",
		TunnelIP:       "10.8.0.7",
		Nodes:          nodes,
		XRay: profile.XRayClientPolicy{
			ServerName: "www.microsoft.com", Fingerprint: "chrome", Flow: "xtls-rprx-vision",
		},
	})
	if len(xrayCP.Nodes) != 1 || xrayCP.Nodes[0].ID != "nod_a" {
		t.Fatalf("xray profile nodes = %+v, want only nod_a", xrayCP.Nodes)
	}
	if got := len(xrayCP.Nodes[0].Protocols); got != 1 || xrayCP.Nodes[0].Protocols[0].Type != profile.ProtocolXRayReality {
		t.Fatalf("nod_a protocols = %+v, want xray-reality only", xrayCP.Nodes[0].Protocols)
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
	if err := json.Unmarshal(xrayCP.Nodes[0].Protocols[0].Params, &xp); err != nil {
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

	// AmneziaWG profile over the same nodes: both qualify, one entry each.
	awgCP := profile.BuildClientProfile(profile.BuildInput{
		SpecID:      "pspec_awg",
		Name:        "Direct",
		Protocol:    profile.ProtocolAmneziaWG,
		DeviceWGKey: "wg-priv",
		TunnelIP:    "10.8.0.7",
		Nodes:       nodes,
	})
	if len(awgCP.Nodes) != 2 {
		t.Fatalf("amneziawg profile nodes = %d, want 2", len(awgCP.Nodes))
	}
	for _, n := range awgCP.Nodes {
		if len(n.Protocols) != 1 || n.Protocols[0].Type != profile.ProtocolAmneziaWG {
			t.Fatalf("node %s protocols = %+v, want amneziawg only", n.ID, n.Protocols)
		}
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
