// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package idgen mints short, prefixed, collision-resistant record identifiers.
package idgen

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// enc is lowercase base32 without padding — 10 random bytes encode to 16 chars.
var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// New returns an identifier of the form "<prefix>_<16 random base32 chars>",
// e.g. New("nod") -> "nod_4k2jq7x9p1m3a8sd". It panics only if the system
// random source fails, which is unrecoverable.
func New(prefix string) string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic("idgen: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + strings.ToLower(enc.EncodeToString(b))
}
