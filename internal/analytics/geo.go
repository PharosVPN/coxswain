// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import "math"

// earthRadiusKM is the mean radius of the Earth, used by the haversine formula.
const earthRadiusKM = 6371.0

// haversineKM returns the great-circle distance in kilometres between two
// (lat, lon) points in degrees — the shortest surface distance, the floor on
// how far a device travelled between two connects.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	rlat1 := lat1 * math.Pi / 180
	rlat2 := lat2 * math.Pi / 180
	dlat := (lat2 - lat1) * math.Pi / 180
	dlon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(dlat/2)*math.Sin(dlat/2) +
		math.Cos(rlat1)*math.Cos(rlat2)*math.Sin(dlon/2)*math.Sin(dlon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKM * c
}

// round2 rounds to two decimals for tidy JSON evidence.
func round2(f float64) float64 {
	return math.Round(f*100) / 100
}
