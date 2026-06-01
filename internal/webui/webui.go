// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package webui embeds the built SvelteKit admin SPA. The build output is
// produced by `cd web && npm run build` and committed under dist/.
package webui

import (
	"embed"
	"io/fs"
)

// all: is required so files under dist/_app (leading underscore) are embedded.
//
//go:embed all:dist
var distFS embed.FS

// FS returns the embedded SPA build, rooted at the dist directory.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("webui: embedded SPA is malformed: " + err.Error())
	}
	return sub
}
