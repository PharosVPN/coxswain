// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package wg_test

import (
	"testing"

	"github.com/PharosVPN/coxswain/internal/wg"
)

func TestObfuscationIsZero(t *testing.T) {
	if !(wg.Obfuscation{}).IsZero() {
		t.Error("empty Obfuscation should be zero")
	}
	// Junk sizes alone, with no magic headers, still count as unconfigured —
	// a real node always sets H1-H4.
	if !(wg.Obfuscation{Jc: 4, S1: 30}).IsZero() {
		t.Error("Obfuscation without magic headers should be zero")
	}
	configured := wg.Obfuscation{H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755}
	if configured.IsZero() {
		t.Error("Obfuscation with magic headers should not be zero")
	}
}

// valid is a structurally sound obfuscation set.
var valid = wg.Obfuscation{
	Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 45, S3: 60, S4: 75,
	H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755,
}

func TestObfuscationValidate(t *testing.T) {
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}

	cases := map[string]wg.Obfuscation{
		"Jmin exceeds Jmax": with(valid, func(o *wg.Obfuscation) { o.Jmin, o.Jmax = 80, 70 }),
		"H below 5":         with(valid, func(o *wg.Obfuscation) { o.H3 = 4 }),
		"H collision":       with(valid, func(o *wg.Obfuscation) { o.H4 = o.H1 }),
		"S2 equals S1+56":   with(valid, func(o *wg.Obfuscation) { o.S1, o.S2 = 30, 86 }),
	}
	for name, o := range cases {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

func with(base wg.Obfuscation, mutate func(*wg.Obfuscation)) wg.Obfuscation {
	mutate(&base)
	return base
}
