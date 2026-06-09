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
	ams2: { lat: 52.37, lon: 4.9, city: 'Amsterdam', country: 'NL', flag: '🇳🇱' },
	// AWS
	'us-east-1': { lat: 38.95, lon: -77.45, city: 'N. Virginia', country: 'US', flag: '🇺🇸' },
	'us-east-2': { lat: 40.0, lon: -83.0, city: 'Ohio', country: 'US', flag: '🇺🇸' },
	'us-west-1': { lat: 37.77, lon: -122.42, city: 'N. California', country: 'US', flag: '🇺🇸' },
	'us-west-2': { lat: 45.84, lon: -119.7, city: 'Oregon', country: 'US', flag: '🇺🇸' },
	'eu-west-1': { lat: 53.41, lon: -8.24, city: 'Ireland', country: 'IE', flag: '🇮🇪' },
	'eu-west-2': { lat: 51.51, lon: -0.13, city: 'London', country: 'UK', flag: '🇬🇧' },
	'eu-central-1': { lat: 50.11, lon: 8.68, city: 'Frankfurt', country: 'DE', flag: '🇩🇪' },
	'ap-southeast-1': { lat: 1.35, lon: 103.82, city: 'Singapore', country: 'SG', flag: '🇸🇬' },
	'ap-southeast-2': { lat: -33.87, lon: 151.21, city: 'Sydney', country: 'AU', flag: '🇦🇺' },
	'ap-northeast-1': { lat: 35.69, lon: 139.69, city: 'Tokyo', country: 'JP', flag: '🇯🇵' },
	'ap-south-1': { lat: 19.08, lon: 72.88, city: 'Mumbai', country: 'IN', flag: '🇮🇳' },
	'sa-east-1': { lat: -23.55, lon: -46.63, city: 'São Paulo', country: 'BR', flag: '🇧🇷' },
	// Hetzner
	nbg1: { lat: 49.45, lon: 11.08, city: 'Nuremberg', country: 'DE', flag: '🇩🇪' },
	fsn1: { lat: 50.48, lon: 12.34, city: 'Falkenstein', country: 'DE', flag: '🇩🇪' },
	hel1: { lat: 60.17, lon: 24.94, city: 'Helsinki', country: 'FI', flag: '🇫🇮' },
	ash: { lat: 39.04, lon: -77.49, city: 'Ashburn', country: 'US', flag: '🇺🇸' },
	hil: { lat: 45.52, lon: -122.99, city: 'Hillsboro', country: 'US', flag: '🇺🇸' },
	// Vultr (a few common codes)
	ewr: { lat: 40.74, lon: -74.17, city: 'New Jersey', country: 'US', flag: '🇺🇸' },
	nrt: { lat: 35.69, lon: 139.69, city: 'Tokyo', country: 'JP', flag: '🇯🇵' },
	cdg: { lat: 48.85, lon: 2.35, city: 'Paris', country: 'FR', flag: '🇫🇷' },
	// GCP (a few common regions)
	'us-central1': { lat: 41.26, lon: -95.86, city: 'Iowa', country: 'US', flag: '🇺🇸' },
	'europe-west1': { lat: 50.45, lon: 3.82, city: 'Belgium', country: 'BE', flag: '🇧🇪' },
	'asia-southeast1': { lat: 1.35, lon: 103.82, city: 'Singapore', country: 'SG', flag: '🇸🇬' }
};

// A neutral mid-ocean point for unknown regions — rare, and the pin still carries
// the raw region code as its label.
const UNKNOWN: GeoLoc = { lat: 25, lon: -40, city: '', country: '', flag: '📍' };

export function locate(region: string | undefined | null): GeoLoc {
	if (!region) return UNKNOWN;
	return REGIONS[region.toLowerCase()] ?? { ...UNKNOWN, city: region };
}

// hasRegion reports whether a code is a recognized region centroid. The map uses
// this to treat a recognized region as an explicit pin override that wins over IP
// geolocation (auto-detected regions are country codes, which aren't listed, so
// IP still wins for them).
export function hasRegion(region: string | undefined | null): boolean {
	return !!region && region.toLowerCase() in REGIONS;
}

// regionOptions lists the known region codes (sorted by label) for the manual
// region-override picker — so the admin can place a node on the map by choosing a
// region instead of relying on IP geolocation. Free-text entry stays allowed for
// any code not listed here.
export function regionOptions(): { code: string; label: string }[] {
	return Object.entries(REGIONS)
		.map(([code, g]) => ({ code, label: `${g.flag} ${g.city} — ${code}` }))
		.sort((a, b) => a.label.localeCompare(b.label));
}
