// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package idgen

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		id := New("nod")
		if !strings.HasPrefix(id, "nod_") {
			t.Fatalf("missing prefix: %q", id)
		}
		if got := strings.TrimPrefix(id, "nod_"); len(got) != 16 {
			t.Fatalf("body length: got %d (%q)", len(got), id)
		}
		if seen[id] {
			t.Fatalf("duplicate id: %q", id)
		}
		seen[id] = true
	}
}
