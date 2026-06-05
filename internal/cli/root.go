// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the coxswain command-line interface.
package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// version is the coxswain build version. Overridable at link time.
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "cox",
		Short:         "PharosVPN controller",
		Long:          "coxswain — the PharosVPN controller and management plane.\n\ncoxswain is the source of truth for the fleet: it holds the CA, drives every\nVPN node over outbound mTLS, and serves the admin UI. It opens no inbound\nports.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newSSHKeyCmd(),
		newServersCmd(),
		newNodesCmd(),
		newPathsCmd(),
		newRelaysCmd(),
		newProfileCmd(),
		newEnrollCmd(),
		newDevicesCmd(),
		newServeCmd(),
	)
	return root
}

// Execute runs the coxswain CLI. The command context is cancelled on SIGINT or
// SIGTERM so long-running commands (cox serve) shut down gracefully.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return newRootCmd().ExecuteContext(ctx)
}
