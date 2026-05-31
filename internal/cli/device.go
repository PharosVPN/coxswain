// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/spf13/cobra"
)

// newDeviceCmd holds device-scoped operations. Today that is the cascade
// exit-switch (DESIGN §3, decision 18): binding a device's traffic to egress
// through a chosen exit, live and server-side.
func newDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Device-scoped operations",
	}
	cmd.AddCommand(newDeviceSetExitCmd(), newDeviceClearExitCmd())
	return cmd
}

func newDeviceSetExitCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "set-exit <device-id> <entry-node-id> <exit-node-id>",
		Short: "Route a device's traffic to egress via an exit node (live switch)",
		Long: "Bind a device, arriving at <entry-node>, to egress through " +
			"<exit-node> over their inner link (create it first with `cox links " +
			"add`). Re-running with a different exit is the live exit-switch: the " +
			"controller flips the route server-side — the client keeps the same " +
			"profile and never re-handshakes.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			coord, err := newCascadeCoordinator(ctx, conn)
			if err != nil {
				return err
			}
			if err := coord.BindExit(ctx, args[0], args[1], args[2]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"device %s now egresses via %s (entry %s)\n", args[0], args[2], args[1])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newDeviceClearExitCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "clear-exit <device-id>",
		Short: "Remove a device's cascade binding (back to normal egress)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			coord, err := newCascadeCoordinator(ctx, conn)
			if err != nil {
				return err
			}
			if err := coord.ClearExit(ctx, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "device %s cascade binding cleared\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}
