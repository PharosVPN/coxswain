// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Command coxswain is the PharosVPN controller / management plane.
package main

import (
	"fmt"
	"os"

	"github.com/PharosVPN/coxswain/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "cox: "+err.Error())
		os.Exit(1)
	}
}
