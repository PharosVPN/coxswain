// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/spf13/cobra"
)

// newControlPathsCmd manages control-plane paths: the fleet-wide route coxswain
// dials OUT through to reach every node's control plane (DESIGN §3). A control
// path is a first-class, named, swappable object — exactly one is active at a
// time; activating another reroutes the whole control plane live with no
// re-onboarding. It is independent of how servers are added or components
// deployed (that is a transient, per-action choice).
func newControlPathsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "control-paths",
		Aliases: []string{"control-path", "cpaths"},
		Short:   "Manage control-plane paths (how coxswain reaches every node)",
		Long: "A control path is a named, ordered chain of relay hops coxswain dials OUT\n" +
			"through to reach every node's control plane, hiding the controller's origin.\n" +
			"Exactly one path is active fleet-wide; activating another reroutes the whole\n" +
			"control plane live, with no re-onboarding. Empty hops = direct. This is\n" +
			"independent of how you add servers or deploy components.",
	}
	cmd.AddCommand(
		newControlPathsAddCmd(),
		newControlPathsListCmd(),
		newControlPathsActivateCmd(),
		newControlPathsRemoveCmd(),
	)
	return cmd
}

func newControlPathsAddCmd() *cobra.Command {
	var cfgPath, viaCSV string
	var activate bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Define a control path (inactive until activated)",
		Long: "Define a named control path from an ordered list of relay ids (--via, hop 1\n" +
			"closest to coxswain, the last hop reaches the node). Omit --via for a direct\n" +
			"path. New paths start inactive — activate one with `cox control-paths activate`,\n" +
			"or pass --activate to do it in one step.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hops := splitCSV(viaCSV)
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := validateRelayHops(ctx, conn, hops); err != nil {
				return err
			}
			cp, err := fleet.CreateControlPath(ctx, conn, fleet.ControlPath{Name: args[0], Hops: hops})
			if err != nil {
				auditCLI(ctx, conn, "control_path.add", "control_path", "", map[string]any{"name": args[0], "hops": hops}, err)
				return err
			}
			if activate {
				if err := fleet.SetActiveControlPath(ctx, conn, cp.ID); err != nil {
					auditCLI(ctx, conn, "control_path.activate", "control_path", cp.ID, nil, err)
					return err
				}
			}
			auditCLI(ctx, conn, "control_path.add", "control_path", cp.ID,
				map[string]any{"name": args[0], "hops": hops, "active": activate}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "control path %s created: %s [%s]%s\n",
				cp.ID, args[0], controlChainText(ctx, conn, hops), activeSuffix(activate))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&viaCSV, "via", "", "ordered relay ids, comma-separated (empty = direct)")
	cmd.Flags().BoolVar(&activate, "activate", false, "activate this path immediately (makes it the fleet control route)")
	return cmd
}

func newControlPathsListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List control paths (the active one is marked ●)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			paths, err := fleet.ListControlPaths(ctx, conn)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no control paths — coxswain reaches nodes directly")
				return nil
			}
			names := relayNameIndex(ctx, conn)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "\tID\tNAME\tROUTE")
			for _, p := range paths {
				marker := " "
				if p.Active {
					marker = "●"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", marker, p.ID, p.Name, chainText(p.Hops, names))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newControlPathsActivateCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "activate <id>",
		Short: "Make a control path the active fleet-wide route (live swap)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := fleet.SetActiveControlPath(ctx, conn, args[0]); err != nil {
				auditCLI(ctx, conn, "control_path.activate", "control_path", args[0], nil, err)
				if errors.Is(err, fleet.ErrNotFound) {
					return fmt.Errorf("no control path %q", args[0])
				}
				return err
			}
			cp, _ := fleet.GetControlPath(ctx, conn, args[0])
			auditCLI(ctx, conn, "control_path.activate", "control_path", args[0], map[string]any{"name": cp.Name}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "control path %s (%s) is now active — coxswain reaches every node via %s\n",
				cp.ID, cp.Name, controlChainText(ctx, conn, cp.Hops))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newControlPathsRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"remove"},
		Short:   "Delete a control path",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			cp, err := fleet.GetControlPath(ctx, conn, args[0])
			if errors.Is(err, fleet.ErrNotFound) {
				return fmt.Errorf("no control path %q", args[0])
			} else if err != nil {
				return err
			}
			if err := fleet.DeleteControlPath(ctx, conn, args[0]); err != nil {
				auditCLI(ctx, conn, "control_path.rm", "control_path", args[0], nil, err)
				return err
			}
			auditCLI(ctx, conn, "control_path.rm", "control_path", args[0], map[string]any{"name": cp.Name}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "control path %s removed\n", args[0])
			if cp.Active {
				fmt.Fprintln(cmd.OutOrStdout(), "  it was active — coxswain now reaches nodes directly (no active path)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

// validateRelayHops checks every hop id resolves to a known relay, so a control
// path can't be defined through a relay that doesn't exist.
func validateRelayHops(ctx context.Context, conn *sql.DB, hops []string) error {
	for _, id := range hops {
		if _, err := fleet.GetRelay(ctx, conn, id); err != nil {
			if errors.Is(err, fleet.ErrNotFound) {
				return fmt.Errorf("unknown relay %q in --via (see `cox relays list`)", id)
			}
			return err
		}
	}
	return nil
}

// relayNameIndex maps relay id → a friendly label for list output (best-effort).
func relayNameIndex(ctx context.Context, conn *sql.DB) map[string]string {
	names := map[string]string{}
	if relays, err := fleet.ListRelays(ctx, conn); err == nil {
		for _, r := range relays {
			label := r.Name
			if label == "" {
				label = r.ID
			}
			names[r.ID] = label
		}
	}
	return names
}

// chainText renders a relay-id hop list as "direct" or "a → b" using names.
func chainText(hops []string, names map[string]string) string {
	if len(hops) == 0 {
		return "direct"
	}
	out := make([]string, len(hops))
	for i, id := range hops {
		if n, ok := names[id]; ok {
			out[i] = n
		} else {
			out[i] = id
		}
	}
	return strings.Join(out, " → ")
}

// controlChainText is chainText with the relay index resolved from conn.
func controlChainText(ctx context.Context, conn *sql.DB, hops []string) string {
	return chainText(hops, relayNameIndex(ctx, conn))
}

func activeSuffix(active bool) string {
	if active {
		return ", now active"
	}
	return ""
}
