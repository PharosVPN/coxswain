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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
