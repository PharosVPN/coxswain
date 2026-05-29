// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package netpolicy turns a node's network policy — forwarding, masquerade,
// client isolation — into the canonical PreUp/PostUp/PostDown rule set
// (DESIGN §3, decision 16). It is the single source of truth coxswain shows in
// the admin UI; buoy applies the same set.
package netpolicy

import "errors"

// Rule-template tokens. buoy substitutes the wg interface for ifaceToken and
// the autodetected egress interface for egressToken.
const (
	ifaceToken  = "%i"
	egressToken = "%e"
)

// ErrMasqueradeNeedsForwarding / ErrIsolationNeedsForwarding report an invalid
// policy: you cannot NAT or isolate traffic that is not forwarded.
var (
	ErrMasqueradeNeedsForwarding = errors.New("netpolicy: masquerade requires forwarding")
	ErrIsolationNeedsForwarding  = errors.New("netpolicy: isolation requires forwarding")
)

// Policy is a node's traffic-handling policy.
type Policy struct {
	Forwarding bool
	Masquerade bool
	Isolation  bool
}

// Validate reports whether the policy is internally consistent.
func (p Policy) Validate() error {
	if p.Masquerade && !p.Forwarding {
		return ErrMasqueradeNeedsForwarding
	}
	if p.Isolation && !p.Forwarding {
		return ErrIsolationNeedsForwarding
	}
	return nil
}

// Rules is the wg-quick-style hook rule set a policy produces.
type Rules struct {
	PreUp    []string `json:"pre_up"`
	PostUp   []string `json:"post_up"`
	PostDown []string `json:"post_down"`
}

// Rules renders the canonical rule set for the policy. The result is what the
// admin UI shows and what buoy applies.
func (p Policy) Rules() Rules {
	var r Rules
	if !p.Forwarding {
		return r // a node that forwards nothing needs no rules
	}

	r.PreUp = []string{
		"sysctl -w net.ipv4.conf.all.forwarding=1",
		"sysctl -w net.ipv6.conf.all.forwarding=1",
	}

	// Isolation drops client-to-client traffic; it must sit above the accepts.
	if p.Isolation {
		r.PostUp = append(r.PostUp,
			"iptables -I FORWARD 1 -i "+ifaceToken+" -o "+ifaceToken+" -j DROP")
		r.PostDown = append(r.PostDown,
			"iptables -D FORWARD -i "+ifaceToken+" -o "+ifaceToken+" -j DROP")
	}

	r.PostUp = append(r.PostUp,
		"iptables -A FORWARD -i "+ifaceToken+" -j ACCEPT",
		"iptables -A FORWARD -o "+ifaceToken+" -j ACCEPT")
	r.PostDown = append(r.PostDown,
		"iptables -D FORWARD -i "+ifaceToken+" -j ACCEPT",
		"iptables -D FORWARD -o "+ifaceToken+" -j ACCEPT")

	if p.Masquerade {
		r.PostUp = append(r.PostUp,
			"iptables -t nat -A POSTROUTING -o "+egressToken+" -j MASQUERADE")
		r.PostDown = append(r.PostDown,
			"iptables -t nat -D POSTROUTING -o "+egressToken+" -j MASQUERADE")
	}
	return r
}
