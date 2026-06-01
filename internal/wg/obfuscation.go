// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package wg

import "fmt"

// Obfuscation is one node's AmneziaWG obfuscation parameter set (DESIGN §3).
// Every node runs AmneziaWG — there is no plain-WireGuard path — and each node
// randomises its own values for traffic diversity, so the set is per-node, not
// fleet-wide. buoy generates and applies it; coxswain stores it and a client must
// receive the exact values to build a tunnel that handshakes.
//
// Field names match the AmneziaWG config keys verbatim:
//
//   - Jc/Jmin/Jmax: junk-packet count and size range
//   - S1-S4: junk sizes for init / response / cookie-reply / transport packets
//   - H1-H4: magic header values for those four packet types
//   - I1-I5: special-junk packet templates injected at handshake stages
type Obfuscation struct {
	Jc   uint32 `json:"jc"`
	Jmin uint32 `json:"jmin"`
	Jmax uint32 `json:"jmax"`
	S1   uint32 `json:"s1"`
	S2   uint32 `json:"s2"`
	S3   uint32 `json:"s3"`
	S4   uint32 `json:"s4"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}

// IsZero reports whether o carries no obfuscation parameters — the state of a
// node that has not yet reported its AmneziaWG configuration. The magic
// headers H1-H4 are always non-zero on a configured node (AmneziaWG reserves
// the low values), so they are the reliable signal.
func (o Obfuscation) IsZero() bool {
	return o.H1 == 0 && o.H2 == 0 && o.H3 == 0 && o.H4 == 0
}

// Validate checks an obfuscation set against AmneziaWG's structural rules.
// buoy generates and enforces these on the node; coxswain re-checks what a node
// reports so a malformed set is rejected loudly rather than silently producing
// profiles that cannot handshake.
func (o Obfuscation) Validate() error {
	if o.Jmin > o.Jmax {
		return fmt.Errorf("wg: obfuscation Jmin (%d) exceeds Jmax (%d)", o.Jmin, o.Jmax)
	}
	// H1-H4 must be four distinct values, each clear of 1-4 — those are
	// reserved for AmneziaWG's four standard packet types.
	hs := [4]uint32{o.H1, o.H2, o.H3, o.H4}
	for i, h := range hs {
		if h < 5 {
			return fmt.Errorf("wg: obfuscation H%d (%d) must be >= 5", i+1, h)
		}
		for j := i + 1; j < len(hs); j++ {
			if h == hs[j] {
				return fmt.Errorf("wg: obfuscation H%d and H%d collide (%d)", i+1, j+1, h)
			}
		}
	}
	// An init packet padded by S1 must not be length-indistinguishable from a
	// response packet padded by S2; the two message types differ by 56 bytes,
	// so S2 == S1+56 collapses that distinction and awg rejects the config.
	if o.S2 == o.S1+56 {
		return fmt.Errorf("wg: obfuscation S2 (%d) must not equal S1+56", o.S2)
	}
	return nil
}
