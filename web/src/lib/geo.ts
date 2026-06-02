// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Approximate geographic locations for cloud regions, so the fleet map can pin a
// node on its real city. The point is recognition ("I come out in Amsterdam"),
// not survey accuracy — a city centroid is plenty.

export interface GeoLoc {
	lat: number;
	lon: number;
	city: string;
	country: string;
	flag: string;
}

// DigitalOcean region codes (the platform's provider) plus a few common AWS
// regions, in case a node reports one. Keys are lowercased on lookup.
const REGIONS: Record<string, GeoLoc> = {
	// DigitalOcean
	nyc1: { lat: 40.71, lon: -74.01, city: 'New York', country: 'US', flag: '🇺🇸' },
	nyc2: { lat: 40.71, lon: -74.01, city: 'New York', country: 'US', flag: '🇺🇸' },
	nyc3: { lat: 40.71, lon: -74.01, city: 'New York', country: 'US', flag: '🇺🇸' },
	sfo1: { lat: 37.77, lon: -122.42, city: 'San Francisco', country: 'US', flag: '🇺🇸' },
	sfo2: { lat: 37.77, lon: -122.42, city: 'San Francisco', country: 'US', flag: '🇺🇸' },
	sfo3: { lat: 37.77, lon: -122.42, city: 'San Francisco', country: 'US', flag: '🇺🇸' },
	tor1: { lat: 43.65, lon: -79.38, city: 'Toronto', country: 'CA', flag: '🇨🇦' },
	ams3: { lat: 52.37, lon: 4.9, city: 'Amsterdam', country: 'NL', flag: '🇳🇱' },
	lon1: { lat: 51.51, lon: -0.13, city: 'London', country: 'UK', flag: '🇬🇧' },
	fra1: { lat: 50.11, lon: 8.68, city: 'Frankfurt', country: 'DE', flag: '🇩🇪' },
	blr1: { lat: 12.97, lon: 77.59, city: 'Bangalore', country: 'IN', flag: '🇮🇳' },
	sgp1: { lat: 1.35, lon: 103.82, city: 'Singapore', country: 'SG', flag: '🇸🇬' },
	syd1: { lat: -33.87, lon: 151.21, city: 'Sydney', country: 'AU', flag: '🇦🇺' },
	// AWS (fallback coverage)
	'us-east-1': { lat: 38.95, lon: -77.45, city: 'N. Virginia', country: 'US', flag: '🇺🇸' },
	'us-west-2': { lat: 45.84, lon: -119.7, city: 'Oregon', country: 'US', flag: '🇺🇸' },
	'eu-west-1': { lat: 53.41, lon: -8.24, city: 'Ireland', country: 'IE', flag: '🇮🇪' },
	'eu-central-1': { lat: 50.11, lon: 8.68, city: 'Frankfurt', country: 'DE', flag: '🇩🇪' },
	'ap-southeast-1': { lat: 1.35, lon: 103.82, city: 'Singapore', country: 'SG', flag: '🇸🇬' }
};

// A neutral mid-ocean point for unknown regions — rare, and the pin still carries
// the raw region code as its label.
const UNKNOWN: GeoLoc = { lat: 25, lon: -40, city: '', country: '', flag: '📍' };

export function locate(region: string | undefined | null): GeoLoc {
	if (!region) return UNKNOWN;
	return REGIONS[region.toLowerCase()] ?? { ...UNKNOWN, city: region };
}
