// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/spf13/cobra"
)

// newLinksCmd manages the node-cascade graph (DESIGN §3, decision 18): the
// entry→exit inner links a device can be routed through.
func newLinksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "links",
		Short: "Manage node-cascade inner links (entry → exit)",
	}
	cmd.AddCommand(newLinksAddCmd(), newLinksListCmd(), newLinksRemoveCmd())
	return cmd
}

func newLinksAddCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "add <entry-node-id> <exit-node-id>",
		Short: "Create an inner link from an entry node to an exit node",
		Args:  cobra.ExactArgs(2),
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
			link, err := coord.ProvisionLink(ctx, args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"link %s created: %s → %s over %s (udp %d), status %s\n",
				link.ID, link.EntryNodeID, link.ExitNodeID, link.InnerInterface,
				link.ListenPort, link.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newLinksListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List node-cascade inner links",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			links, err := fleet.ListNodeLinks(ctx, conn)
			if err != nil {
				return err
			}
			if len(links) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no inner links")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tENTRY\tEXIT\tIFACE\tPORT\tSTATUS")
			for _, l := range links {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
					l.ID, l.EntryNodeID, l.ExitNodeID, l.InnerInterface, l.ListenPort, l.Status)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newLinksRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "rm <link-id>",
		Aliases: []string{"remove"},
		Short:   "Tear down an inner link",
		Args:    cobra.ExactArgs(1),
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
			if err := coord.DeprovisionLink(ctx, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "link %s removed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}
