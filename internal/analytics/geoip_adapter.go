// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import "github.com/PharosVPN/coxswain/internal/geoip"

// geoipResolver is the minimal slice of *geoip.Resolver the adapter needs,
// declared as an interface so the adapter itself stays testable.
type geoipResolver interface {
	Lookup(host string) (geoip.Location, bool)
}

// FromGeoIP adapts a *geoip.Resolver (or anything Lookup-shaped) to the engine's
// GeoResolver, translating geoip.Location to the engine's local Location. A nil
// resolver yields a GeoResolver that never resolves, so geo-dependent rules just
// skip — the engine never depends on a downloaded MaxMind database being present.
func FromGeoIP(r *geoip.Resolver) GeoResolver {
	if r == nil {
		return noGeo{}
	}
	return geoAdapter{r: r}
}

type geoAdapter struct{ r geoipResolver }

func (a geoAdapter) Lookup(host string) (Location, bool) {
	loc, ok := a.r.Lookup(host)
	if !ok {
		return Location{}, false
	}
	return Location{
		City:        loc.City,
		Country:     loc.Country,
		CountryCode: loc.CountryCode,
		Latitude:    loc.Latitude,
		Longitude:   loc.Longitude,
	}, true
}
