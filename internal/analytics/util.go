// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"math"
	"sort"
)

// keys returns the sorted keys of a string-set, for stable JSON evidence.
func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nonEmpty wraps a single source IP into the []string a Finding carries, or an
// empty slice when the IP is blank — so a finding never records a "" source IP.
func nonEmpty(ip string) []string {
	if ip == "" {
		return nil
	}
	return []string{ip}
}

// round4 rounds a fraction to 4 decimal places for compact, stable JSON
// evidence (a share like 0.0123 rather than a long float tail).
func round4(f float64) float64 {
	return math.Round(f*1e4) / 1e4
}
