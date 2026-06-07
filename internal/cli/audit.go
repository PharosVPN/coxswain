// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os/user"
	"text/tabwriter"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/monitor"
	"github.com/spf13/cobra"
)

// osUser returns the local OS username, used as the actor for CLI mutations
// (actor_kind = "cli"). Falls back to "cli" if the user can't be resolved.
func osUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "cli"
}

// auditCLI records a CLI mutation in the audit log: actor = the OS user, kind =
// "cli". A non-nil err marks the row result=error. The DB-write error is
// ignored — auditing must never break the command it records.
func auditCLI(ctx context.Context, conn *sql.DB, action, targetType, targetID string, detail map[string]any, err error) {
	_ = audit.Log(ctx, conn, audit.Entry{
		Actor:      osUser(),
		ActorKind:  audit.KindCLI,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Detail:     detail,
		Err:        err,
	})
}

// runAuditPurge deletes audit rows older than days, on startup and once a day
// after, until ctx is cancelled. days <= 0 disables retention (a no-op). Errors
// are non-fatal — they print a warning and the next tick retries.
func runAuditPurge(ctx context.Context, conn *sql.DB, days int) {
	if days <= 0 {
		return
	}
	purge := func() {
		if n, err := audit.Purge(ctx, conn, days); err != nil {
			fmt.Printf("  audit:   purge failed (will retry): %v\n", err)
		} else if n > 0 {
			fmt.Printf("  audit:   purged %d entr%s older than %dd\n", n, plural(n), days)
		}
	}
	purge()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

// runHistoryPurge deletes connection_events older than days, on startup and
// once a day after, until ctx is cancelled. days <= 0 disables history
// retention (a no-op). Errors are non-fatal — a warning prints and the next
// tick retries. It reuses retention.metrics_days (same time-series class).
func runHistoryPurge(ctx context.Context, conn *sql.DB, days int) {
	if days <= 0 {
		return
	}
	purge := func() {
		if n, err := monitor.Purge(ctx, conn, days); err != nil {
			fmt.Printf("  history: purge failed (will retry): %v\n", err)
		} else if n > 0 {
			fmt.Printf("  history: purged %d connection event(s) older than %dd\n", n, days)
		}
	}
	purge()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

// runAlertsPurge deletes analytics alerts older than days, on startup and once
// a day after, until ctx is cancelled. days <= 0 disables alerts retention (a
// no-op). Errors are non-fatal — a warning prints and the next tick retries. It
// reuses retention.metrics_days (same time-series class as the history alerts
// derive from).
func runAlertsPurge(ctx context.Context, conn *sql.DB, days int) {
	if days <= 0 {
		return
	}
	purge := func() {
		if n, err := analytics.Purge(ctx, conn, days); err != nil {
			fmt.Printf("  alerts:  purge failed (will retry): %v\n", err)
		} else if n > 0 {
			fmt.Printf("  alerts:  purged %d alert(s) older than %dd\n", n, days)
		}
	}
	purge()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

func plural(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// newAuditCmd prints recent audit-log entries, newest first.
func newAuditCmd() *cobra.Command {
	var cfgPath, action, actor, targetID string
	var sinceDur time.Duration
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent management audit-log entries",
		Long: "Print the audit trail — every management mutation (who, what, target,\n" +
			"result), newest first. Filter by --action, --actor, --target, a relative\n" +
			"--since window, and cap with --limit.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			f := audit.Filter{Action: action, Actor: actor, TargetID: targetID, Limit: limit}
			if sinceDur > 0 {
				f.Since = time.Now().UTC().Add(-sinceDur)
			}
			records, err := audit.Query(ctx, conn, f)
			if err != nil {
				return err
			}
			if len(records) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no audit entries")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tACTOR\tKIND\tACTION\tTARGET\tRESULT\tERROR")
			for _, e := range records {
				target := e.TargetType
				if e.TargetID != "" {
					target += " " + e.TargetID
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					e.At.Local().Format(time.RFC3339), dash(e.Actor), e.ActorKind, e.Action,
					dash(target), e.Result, e.Error)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&action, "action", "", "filter by action (e.g. node.add)")
	cmd.Flags().StringVar(&actor, "actor", "", "filter by actor")
	cmd.Flags().StringVar(&targetID, "target", "", "filter by target id")
	cmd.Flags().DurationVar(&sinceDur, "since", 0, "only entries newer than this window (e.g. 24h)")
	cmd.Flags().IntVar(&limit, "limit", audit.DefaultLimit, "max entries to show (capped at 1000)")
	return cmd
}
