// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package netpolicy turns a node's network policy — forwarding, masquerade,
// client isolation — into the canonical PreUp/PostUp/PostDown rule set
// (DESIGN §3, decision 16). It is the single source of truth coxswain shows in
// the admin UI; buoy applies the same set.
package netpolicy

import (
	"errors"
	"strconv"
)

// Rule-template tokens. buoy substitutes the wg interface for ifaceToken and
// the autodetected egress interface for egressToken.
const (
	ifaceToken  = "%i"
	egressToken = "%e"
)

// Policy validation errors. masquerade, isolation and transit all require
// forwarding; you cannot NAT, isolate, or transit traffic that is not forwarded.
var (
	ErrMasqueradeNeedsForwarding = errors.New("netpolicy: masquerade requires forwarding")
	ErrIsolationNeedsForwarding  = errors.New("netpolicy: isolation requires forwarding")
	ErrTransitNeedsForwarding    = errors.New("netpolicy: transit routes require forwarding")
	ErrTransitIncomplete         = errors.New("netpolicy: transit route needs device_cidr, inner_interface, mark and table")
)

// TransitRoute policy-routes one cascaded device into an inner link toward its
// exit instead of the public egress — the entry-node side of node cascade
// (DESIGN §3, decision 18). It mirrors buoy's netpolicy.TransitRoute and the
// pharos.buoy.v1.TransitRoute wire message; the rendered rule must stay
// byte-identical to buoy's (both pinned by tests).
type TransitRoute struct {
	DeviceCIDR     string
	InnerInterface string
	Mark           uint32
	Table          uint32
}

// Policy is a node's traffic-handling policy.
type Policy struct {
	Forwarding bool
	Masquerade bool
	Isolation  bool
	// Transits route specific devices into inner links (node cascade).
	Transits []TransitRoute
}

// Validate reports whether the policy is internally consistent.
func (p Policy) Validate() error {
	if p.Masquerade && !p.Forwarding {
		return ErrMasqueradeNeedsForwarding
	}
	if p.Isolation && !p.Forwarding {
		return ErrIsolationNeedsForwarding
	}
	if len(p.Transits) > 0 && !p.Forwarding {
		return ErrTransitNeedsForwarding
	}
	for _, t := range p.Transits {
		if t.DeviceCIDR == "" || t.InnerInterface == "" || t.Mark == 0 || t.Table == 0 {
			return ErrTransitIncomplete
		}
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

	// Transit (node cascade): mark each cascaded device, policy-route the mark
	// into the device's inner interface, and add a default route in that table.
	// Transited packets egress the inner interface, never matching the egress
	// masquerade above — the exit node NATs them. Mirrors buoy exactly.
	//
	// A return from the exit arrives on the inner interface, but the route back
	// to its source (the public destination) is the egress interface — an
	// asymmetric path that reverse-path filtering drops, even in loose mode, so
	// the entry silently fails to forward returns to the client. Relax rp_filter
	// while the node carries transits. The effective value is max(all, iface),
	// so `all` must be relaxed — relaxing only the inner interface is a no-op.
	if len(p.Transits) > 0 {
		r.PreUp = append(r.PreUp, "sysctl -w net.ipv4.conf.all.rp_filter=0")
		r.PostDown = append(r.PostDown, "sysctl -w net.ipv4.conf.all.rp_filter=2")
	}
	for _, t := range p.Transits {
		mark := strconv.FormatUint(uint64(t.Mark), 10)
		table := strconv.FormatUint(uint64(t.Table), 10)
		r.PostUp = append(r.PostUp,
			"iptables -t mangle -A PREROUTING -i "+ifaceToken+" -s "+t.DeviceCIDR+" -j MARK --set-mark "+mark,
			"ip rule add fwmark "+mark+" lookup "+table,
			"ip route add default dev "+t.InnerInterface+" table "+table)
		r.PostDown = append(r.PostDown,
			"ip route del default dev "+t.InnerInterface+" table "+table,
			"ip rule del fwmark "+mark+" lookup "+table,
			"iptables -t mangle -D PREROUTING -i "+ifaceToken+" -s "+t.DeviceCIDR+" -j MARK --set-mark "+mark)
	}
	return r
}
