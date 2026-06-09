// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package agentver reads and compares agent (node/relay) build versions.
//
// The version source is the binary's embedded Go build info (the VCS-stamped
// module version, e.g. v0.3.3-0.20260608014009-35a2ef86f503), NOT the agent's
// `version` subcommand — that prints a link-time var that defaults to a
// placeholder ("0.1.0-dev") unless explicitly stamped, so it is unreliable for
// deciding whether a newer build is available. buildinfo, by contrast, is
// stamped from VCS for every `go build` (Go 1.24+) and is always present.
//
// coxswain reads the candidate version straight from the binary BYTES it is
// about to upload (FromBinary), so a node's recorded "deployed" version and the
// "available" version of the configured binary are produced the same way and
// compare cleanly with golang.org/x/mod/semver.
package agentver

import (
	"bytes"
	"debug/buildinfo"
	"strings"

	"golang.org/x/mod/semver"
)

// FromBinary returns the embedded module version of a Go binary's bytes, or ""
// when the bytes are not a recognizable Go binary or carry no usable version
// (e.g. a bare "go build" without VCS info reports "(devel)"). Best-effort: a
// blank result simply means "unknown", which callers treat as not-comparable.
func FromBinary(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	return cleanVersion(info.Main.Version)
}

// FromFile is FromBinary for a binary already on disk (e.g. the configured
// node.binary_path / relay.binary_path).
func FromFile(path string) string {
	if path == "" {
		return ""
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return ""
	}
	return cleanVersion(info.Main.Version)
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "(devel)" {
		return ""
	}
	return v
}

// Normalize coerces a recorded version string into a form golang.org/x/mod/semver
// accepts: it strips a leading agent-name prefix ("node "/"relay ") that the
// `version` subcommand may have emitted, trims spaces, and ensures a leading "v".
// Returns "" when the result is not valid semver (so callers can treat it as
// unknown rather than mis-compare).
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// Drop an agent-name prefix like "node 0.3.3" or "relay v0.1.0".
	if i := strings.LastIndex(v, " "); i >= 0 {
		v = v[i+1:]
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

// UpdateAvailable reports whether the available build is strictly newer than the
// deployed build. It returns false whenever either version is unknown or not
// valid semver — an honest "can't tell" never surfaces a misleading Update
// prompt. Pseudo-versions order correctly (v0.3.3-0.2026… < v0.3.3) via semver.
func UpdateAvailable(deployed, available string) bool {
	d, a := Normalize(deployed), Normalize(available)
	if d == "" || a == "" {
		return false
	}
	return semver.Compare(a, d) > 0
}

// Display renders a version for humans: a tagged release passes through (v0.3.3),
// while a Go pseudo-version (v0.3.3-0.20260608014009-35a2ef86f503) collapses to
// its base plus the short commit (v0.3.3-dev+35a2ef8). Unknown stays "".
func Display(v string) string {
	n := Normalize(v)
	if n == "" {
		return strings.TrimSpace(v)
	}
	pre := semver.Prerelease(n) // "" for a clean tag, "-0.2026…-<rev>" for a pseudo
	if pre == "" {
		return n
	}
	base := strings.TrimSuffix(n, pre)
	// A Go pseudo-version's prerelease ends with "-<12-hex-commit>".
	if i := strings.LastIndex(pre, "-"); i >= 0 && len(pre)-i-1 >= 7 {
		rev := pre[i+1:]
		if len(rev) > 7 {
			rev = rev[:7]
		}
		return base + "-dev+" + rev
	}
	return n
}
