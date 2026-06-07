// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/spf13/cobra"
)

// newAlertsCmd groups the anomaly-detection alert commands (Phase C): list the
// engine's findings and acknowledge/resolve them. Like the other state-reading
// commands, these operate directly on the local state database.
func newAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "List and manage analytics anomaly alerts",
		Long: "Show the analytics engine's anomaly alerts — leaked profiles,\n" +
			"impossible travel, concurrent sessions, and new-geo connects — and\n" +
			"acknowledge or resolve them. Filter by --status, --kind, --severity.",
		// Bare `cox alerts` lists, mirroring `cox audit`.
		RunE: runAlertsList,
	}
	addAlertsListFlags(cmd)
	cmd.AddCommand(newAlertsAckCmd(), newAlertsResolveCmd())
	return cmd
}

func addAlertsListFlags(cmd *cobra.Command) {
	cmd.Flags().String("config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().String("status", "", "filter by status (open | acknowledged | resolved)")
	cmd.Flags().String("kind", "", "filter by kind (e.g. leaked_profile)")
	cmd.Flags().String("severity", "", "filter by severity (info | warning | critical)")
	cmd.Flags().String("device", "", "filter by device id")
	cmd.Flags().Int("limit", analytics.DefaultLimit, "max alerts to show (capped at 1000)")
}

func runAlertsList(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	cfgPath, _ := cmd.Flags().GetString("config")
	cfg, conn, err := openState(cfgPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	status, _ := cmd.Flags().GetString("status")
	kind, _ := cmd.Flags().GetString("kind")
	severity, _ := cmd.Flags().GetString("severity")
	device, _ := cmd.Flags().GetString("device")
	limit, _ := cmd.Flags().GetInt("limit")

	alerts, err := analytics.Query(ctx, conn, analytics.Filter{
		Status: status, Kind: kind, Severity: severity, DeviceID: device, Limit: limit,
	})
	if err != nil {
		return err
	}

	// Surface the backend-suitability warning once, like the API envelope.
	if w := analytics.BackendWarning(cfg.BackendKind()); w != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
	}

	if len(alerts) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no alerts")
		return nil
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME\tKIND\tSEVERITY\tSTATUS\tDEVICE\tSOURCE-IPS")
	for _, a := range alerts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.ID, a.At.Local().Format(time.RFC3339), a.Kind, a.Severity, a.Status,
			dash(a.DeviceID), dash(strings.Join(a.SourceIPs, ",")))
	}
	return tw.Flush()
}

func newAlertsAckCmd() *cobra.Command {
	return newAlertsStatusCmd("ack", analytics.StatusAcknowledged, "alert.ack", "Acknowledge an alert")
}

func newAlertsResolveCmd() *cobra.Command {
	return newAlertsStatusCmd("resolve", analytics.StatusResolved, "alert.resolve", "Resolve an alert")
}

// newAlertsStatusCmd builds an ack/resolve subcommand: it transitions the
// alert's status and writes an audit row, mirroring the API mutations.
func newAlertsStatusCmd(use, status, action, short string) *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   use + " <alert-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			id := args[0]
			if err := analytics.SetStatus(ctx, conn, id, status, time.Now().UTC()); err != nil {
				auditCLI(ctx, conn, action, "alert", id, nil, err)
				return err
			}
			auditCLI(ctx, conn, action, "alert", id, map[string]any{"status": status}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "alert %s %s\n", id, status)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}
