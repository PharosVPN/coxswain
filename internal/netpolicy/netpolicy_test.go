// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package netpolicy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PharosVPN/coxswain/internal/netpolicy"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  netpolicy.Policy
		wantErr error
	}{
		{"forwarding only", netpolicy.Policy{Forwarding: true}, nil},
		{"full", netpolicy.Policy{Forwarding: true, Masquerade: true, Isolation: true}, nil},
		{"all off", netpolicy.Policy{}, nil},
		{"masquerade no forwarding", netpolicy.Policy{Masquerade: true}, netpolicy.ErrMasqueradeNeedsForwarding},
		{"isolation no forwarding", netpolicy.Policy{Isolation: true}, netpolicy.ErrIsolationNeedsForwarding},
		{"transit no forwarding", netpolicy.Policy{Transits: []netpolicy.TransitRoute{{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 7100, Table: 7100}}}, netpolicy.ErrTransitNeedsForwarding},
		{"transit incomplete", netpolicy.Policy{Forwarding: true, Transits: []netpolicy.TransitRoute{{DeviceCIDR: "10.8.0.5/32"}}}, netpolicy.ErrTransitIncomplete},
		{"transit valid", netpolicy.Policy{Forwarding: true, Transits: []netpolicy.TransitRoute{{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 7100, Table: 7100}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate: got %v want %v", err, tc.wantErr)
			}
		})
	}
}

// TestRulesTransit pins the transit rule set. These strings are the cross-repo
// contract with buoy/internal/netpolicy — they MUST match buoy's
// TestTransitRulesCanonical exactly, or preview (here) and apply (buoy) diverge.
func TestRulesTransit(t *testing.T) {
	p := netpolicy.Policy{
		Forwarding: true,
		Masquerade: true,
		Transits: []netpolicy.TransitRoute{
			{DeviceCIDR: "10.8.0.5/32", InnerInterface: "awg1", Mark: 100, Table: 100},
		},
	}
	r := p.Rules()
	up := strings.Join(r.PostUp, "\n")
	down := strings.Join(r.PostDown, "\n")
	for _, want := range []string{
		"iptables -t mangle -A PREROUTING -i %i -s 10.8.0.5/32 -j MARK --set-mark 100",
		"ip rule add fwmark 100 lookup 100",
		"ip route add default dev awg1 table 100",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("PostUp missing %q\n got:\n%s", want, up)
		}
	}
	for _, want := range []string{
		"ip route del default dev awg1 table 100",
		"ip rule del fwmark 100 lookup 100",
		"iptables -t mangle -D PREROUTING -i %i -s 10.8.0.5/32 -j MARK --set-mark 100",
	} {
		if !strings.Contains(down, want) {
			t.Errorf("PostDown missing %q\n got:\n%s", want, down)
		}
	}

	// A transit node forwards returns asymmetrically (in on the inner interface,
	// route-back via egress), which rp_filter drops — so the cascade entry must
	// relax it while it carries transits, and restore it on teardown. Matches
	// buoy's TestTransitRulesCanonical.
	if !strings.Contains(strings.Join(r.PreUp, "\n"), "sysctl -w net.ipv4.conf.all.rp_filter=0") {
		t.Errorf("PreUp missing the rp_filter relax\n got: %#v", r.PreUp)
	}
	if !strings.Contains(down, "sysctl -w net.ipv4.conf.all.rp_filter=2") {
		t.Errorf("PostDown missing the rp_filter restore\n got: %#v", r.PostDown)
	}
}

// TestRulesNoTransitKeepsRpFilter guards that a plain forwarding node keeps
// reverse-path filtering — the relax is scoped to cascade transit nodes only.
func TestRulesNoTransitKeepsRpFilter(t *testing.T) {
	r := netpolicy.Policy{Forwarding: true, Masquerade: true}.Rules()
	if strings.Contains(strings.Join(r.PreUp, "\n"), "rp_filter") {
		t.Errorf("non-transit node must not touch rp_filter\n got: %#v", r.PreUp)
	}
}

func TestRulesForwardingOff(t *testing.T) {
	r := netpolicy.Policy{}.Rules()
	if len(r.PreUp) != 0 || len(r.PostUp) != 0 || len(r.PostDown) != 0 {
		t.Errorf("forwarding off should yield no rules, got %+v", r)
	}
}

func TestRulesFull(t *testing.T) {
	r := netpolicy.Policy{Forwarding: true, Masquerade: true, Isolation: true}.Rules()

	joined := strings.Join(r.PostUp, "\n")
	for _, want := range []string{"MASQUERADE", "-i %i -o %i -j DROP", "-A FORWARD -i %i -j ACCEPT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("PostUp missing %q\n%s", want, joined)
		}
	}
	// Isolation DROP must be inserted at the top of the chain, before accepts.
	if !strings.HasPrefix(r.PostUp[0], "iptables -I FORWARD 1") {
		t.Errorf("isolation DROP must come first, got %q", r.PostUp[0])
	}
	if len(r.PostDown) != len(r.PostUp) {
		t.Errorf("PostDown (%d) must mirror PostUp (%d)", len(r.PostDown), len(r.PostUp))
	}
	if len(r.PreUp) == 0 {
		t.Error("forwarding should emit sysctl PreUp rules")
	}
}

func TestRulesForwardingOnly(t *testing.T) {
	r := netpolicy.Policy{Forwarding: true}.Rules()
	joined := strings.Join(r.PostUp, "\n")
	if strings.Contains(joined, "MASQUERADE") || strings.Contains(joined, "DROP") {
		t.Errorf("forwarding-only must not NAT or isolate:\n%s", joined)
	}
}
