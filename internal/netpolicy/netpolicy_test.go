// SPDX-License-Identifier: AGPL-3.0-or-later
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate: got %v want %v", err, tc.wantErr)
			}
		})
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
