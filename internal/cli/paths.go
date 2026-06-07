// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/spf13/cobra"
)

// newPathsCmd manages data-plane paths (DESIGN §3, decision 18): named,
// ordered chains entry → [mid] → exit that a client's traffic traverses. A path
// is defined before clients, and a client is then bound onto one.
func newPathsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "paths",
		Short: "Manage data-plane paths (entry → [mid] → exit)",
	}
	cmd.AddCommand(
		newPathsAddCmd(),
		newPathsListCmd(),
		newPathsProvisionCmd(),
		newPathsRemoveCmd(),
		newPathsBindCmd(),
		newPathsUnbindCmd(),
		newPathsColorCmd(),
	)
	return cmd
}

func newPathsAddCmd() *cobra.Command {
	var cfgPath, hopsCSV, color string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Define a path and provision its inner-link chain",
		Long: "Define a path from an ordered list of node ids (--hops, entry first, " +
			"exit last, at most one mid) and bring up the inner AmneziaWG link " +
			"between each consecutive hop. Bind a client onto it with `cox paths bind`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hops := splitCSV(hopsCSV)
			if len(hops) < 2 {
				return fmt.Errorf("--hops needs at least an entry and an exit (comma-separated node ids)")
			}
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			coord, err := newCascadeCoordinator(ctx, conn)
			if err != nil {
				return err
			}
			p, err := fleet.CreatePath(ctx, conn, args[0], color, hops)
			if err != nil {
				auditCLI(ctx, conn, "path.add", "path", "", map[string]any{"name": args[0], "hops": hops}, err)
				return err
			}
			if _, err := coord.ProvisionPath(ctx, p.ID); err != nil {
				// Roll back so a failed provision leaves no dangling path.
				_ = coord.DeprovisionPath(ctx, p.ID)
				_ = fleet.DeletePath(ctx, conn, p.ID)
				auditCLI(ctx, conn, "path.add", "path", p.ID, map[string]any{"name": args[0], "hops": hops}, err)
				return fmt.Errorf("provision path: %w", err)
			}
			auditCLI(ctx, conn, "path.add", "path", p.ID, map[string]any{"name": args[0], "hops": hops}, nil)
			fmt.Fprintf(cmd.OutOrStdout(),
				"path %s created: %s [%s], status active\n", p.ID, args[0], strings.Join(hops, " → "))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&hopsCSV, "hops", "", "ordered node ids, comma-separated: entry[,mid],exit")
	cmd.Flags().StringVar(&color, "color", "", "map colour for this path, e.g. #4fd1c4 (optional; auto-assigned if empty)")
	_ = cmd.MarkFlagRequired("hops")
	return cmd
}

func newPathsListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List data-plane paths",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			paths, err := fleet.ListPaths(ctx, conn)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no paths")
				return nil
			}
			names := nodeNameIndex(ctx, conn)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tCHAIN\tSTATUS")
			for _, p := range paths {
				hops, _ := fleet.ListPathHops(ctx, conn, p.ID)
				chain := make([]string, len(hops))
				for i, h := range hops {
					if n, ok := names[h.NodeID]; ok {
						chain[i] = n
					} else {
						chain[i] = h.NodeID
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, p.Name, strings.Join(chain, " → "), p.Status)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newPathsProvisionCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "provision <path-id>",
		Short: "Re-apply a path's inner-link chain (idempotent heal)",
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
			if _, err := coord.ProvisionPath(ctx, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "path %s provisioned\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newPathsRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "rm <path-id>",
		Aliases: []string{"remove"},
		Short:   "Tear down a path's inner-link chain",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			// Data-plane-safe: refuse while a client is bound (re-bind it first),
			// so no profile silently changes its route.
			if bound, err := fleet.ListDeviceIDsByPath(ctx, conn, args[0]); err != nil {
				return err
			} else if len(bound) > 0 {
				return fmt.Errorf("%d client(s) are bound to this path — re-bind them with `cox paths bind` first", len(bound))
			}
			coord, err := newCascadeCoordinator(ctx, conn)
			if err != nil {
				return err
			}
			if err := coord.DeprovisionPath(ctx, args[0]); err != nil {
				auditCLI(ctx, conn, "path.rm", "path", args[0], nil, err)
				return err
			}
			auditCLI(ctx, conn, "path.rm", "path", args[0], nil, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "path %s removed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newPathsBindCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "bind <device-id> <path-id>",
		Short: "Route a device's traffic onto a path (live switch)",
		Long: "Bind a device's traffic to egress along a path (the device must " +
			"already have a tunnel on the path entry). Re-binding to a different " +
			"path is the live switch.",
		Args: cobra.ExactArgs(2),
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
			if err := coord.BindDeviceToPath(ctx, args[0], args[1]); err != nil {
				auditCLI(ctx, conn, "path.bind", "device", args[0], map[string]any{"path_id": args[1]}, err)
				return err
			}
			auditCLI(ctx, conn, "path.bind", "device", args[0], map[string]any{"path_id": args[1]}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "device %s bound to path %s\n", args[0], args[1])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newPathsUnbindCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "unbind <device-id>",
		Short: "Remove a device's path binding (back to normal egress)",
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
			if err := coord.ClearDevicePath(ctx, args[0]); err != nil {
				auditCLI(ctx, conn, "path.unbind", "device", args[0], nil, err)
				return err
			}
			auditCLI(ctx, conn, "path.unbind", "device", args[0], nil, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "device %s path binding cleared\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newPathsColorCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "color <path-id> <hex>",
		Short: "Set a path's colour on the map",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := fleet.SetPathColor(cmd.Context(), conn, args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "path %s colour set to %s\n", args[0], args[1])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

// splitCSV splits a comma-separated list, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// nodeNameIndex maps node id → name for friendly list output (best-effort).
func nodeNameIndex(ctx context.Context, conn *sql.DB) map[string]string {
	names := map[string]string{}
	if nodes, err := fleet.ListNodes(ctx, conn); err == nil {
		for _, n := range nodes {
			names[n.ID] = n.Name
		}
	}
	return names
}
