// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"math"
	"testing"
)

// TestHaversineKnownDistances checks the great-circle math against published
// city-pair distances (within a 2% tolerance — the formula is exact, the city
// coordinates are approximate), so the impossible-travel speed is trustworthy.
func TestHaversineKnownDistances(t *testing.T) {
	cases := []struct {
		name                   string
		lat1, lon1, lat2, lon2 float64
		wantKM                 float64
	}{
		{"NYC-London", 40.71, -74.01, 51.51, -0.13, 5570},
		{"NYC-Tokyo", 40.71, -74.01, 35.68, 139.69, 10850},
		{"London-Tokyo", 51.51, -0.13, 35.68, 139.69, 9560},
		{"same-point", 40.71, -74.01, 40.71, -74.01, 0},
	}
	for _, c := range cases {
		got := haversineKM(c.lat1, c.lon1, c.lat2, c.lon2)
		if c.wantKM == 0 {
			if got != 0 {
				t.Errorf("%s: got %.1f km want 0", c.name, got)
			}
			continue
		}
		if rel := math.Abs(got-c.wantKM) / c.wantKM; rel > 0.02 {
			t.Errorf("%s: got %.1f km want ~%.0f km (%.1f%% off)", c.name, got, c.wantKM, rel*100)
		}
	}
}
