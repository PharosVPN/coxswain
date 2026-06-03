// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package geoip resolves a server's location from its IP using a MaxMind
// GeoLite2-City database, so the admin never types a region — it's derived
// from the host. The database is large and licensed, so it's loaded from a
// file path (never embedded); when absent, lookups simply report "unknown"
// and the UI falls back to its region-code map.
package geoip

import (
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Location is a resolved IP location for the map and server cards.
type Location struct {
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// Resolver looks up IP locations against an open GeoLite2-City database. A nil
// or unavailable Resolver is safe to use — Lookup just returns ok=false.
type Resolver struct {
	mu sync.RWMutex
	db *geoip2.Reader
}

// Open returns a Resolver backed by the first readable GeoLite2-City.mmdb among
// paths (empty paths are skipped). It never errors: if none open, the Resolver
// is unavailable and Lookup reports ok=false.
func Open(paths ...string) *Resolver {
	r := &Resolver{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if db, err := geoip2.Open(p); err == nil {
			r.db = db
			break
		}
	}
	return r
}

// Available reports whether a database is loaded.
func (r *Resolver) Available() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db != nil
}

// Lookup resolves an IP (or host:port — the port is ignored) to a Location.
// ok is false for a private/invalid IP, an unavailable database, or a record
// with no coordinates.
func (r *Resolver) Lookup(host string) (Location, bool) {
	if r == nil {
		return Location{}, false
	}
	r.mu.RLock()
	db := r.db
	r.mu.RUnlock()
	if db == nil {
		return Location{}, false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() {
		return Location{}, false
	}
	rec, err := db.City(ip)
	if err != nil {
		return Location{}, false
	}
	loc := Location{
		City:        rec.City.Names["en"],
		Country:     rec.Country.Names["en"],
		CountryCode: rec.Country.IsoCode,
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
	}
	if loc.Latitude == 0 && loc.Longitude == 0 && loc.CountryCode == "" {
		return Location{}, false
	}
	return loc, true
}

// Close releases the database.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db != nil {
		err := r.db.Close()
		r.db = nil
		return err
	}
	return nil
}
