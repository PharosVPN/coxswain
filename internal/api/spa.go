// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/PharosVPN/coxswain/internal/webui"
)

// spaHandler serves the embedded SvelteKit admin SPA. Real asset paths are
// served from the embedded build; every other path falls back to index.html
// so the client router can handle it.
func spaHandler() http.Handler {
	fsys := webui.FS()
	fileServer := http.FileServerFS(fsys)
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		panic("api: embedded SPA missing index.html: " + err.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean != "" && clean != "index.html" {
			if f, err := fsys.Open(clean); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Client-side route — serve the SPA shell.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
