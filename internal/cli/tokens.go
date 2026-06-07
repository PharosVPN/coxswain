// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/spf13/cobra"
)

// newTokensCmd groups scoped API-token management. A token is a bearer
// credential for the admin API alongside the session cookie; it carries one
// scope (readonly < monitor < admin) that gates what its bearer may do.
func newTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "Manage scoped API tokens (bearer credentials for the admin API)",
	}
	cmd.AddCommand(
		newTokensCreateCmd(),
		newTokensListCmd(),
		newTokensRevokeCmd(),
	)
	return cmd
}

func newTokensCreateCmd() *cobra.Command {
	var cfgPath, scope string
	var expires time.Duration
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint a scoped API token (prints the secret once)",
		Long: "Create an API token with a scope — readonly (GET only), monitor (reads +\n" +
			"the live event stream), or admin (full mutations). The plaintext secret\n" +
			"is printed exactly once and never stored; copy it now. Use it as\n" +
			"`Authorization: Bearer <secret>`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			sc, err := authn.ParseScope(scope)
			if err != nil {
				return err
			}
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			secret, rec, err := authn.Create(ctx, conn, args[0], sc, expires, osUser())
			if err != nil {
				auditCLI(ctx, conn, "token.create", "token", "", map[string]any{"name": args[0], "scope": scope}, err)
				return err
			}
			auditCLI(ctx, conn, "token.create", "token", rec.ID, map[string]any{"name": rec.Name, "scope": string(rec.Scope)}, nil)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "token %s created — scope %s\n", rec.ID, rec.Scope)
			if rec.ExpiresAt != nil {
				fmt.Fprintf(out, "  expires  %s\n", rec.ExpiresAt.Local().Format(time.RFC3339))
			} else {
				fmt.Fprintln(out, "  expires  never")
			}
			fmt.Fprintf(out, "\n  secret   %s\n\n", secret)
			fmt.Fprintln(out, "  store it now — it won't be shown again.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&scope, "scope", string(authn.ScopeReadonly), "token scope: readonly | monitor | admin")
	cmd.Flags().DurationVar(&expires, "expires", 0, "token lifetime (e.g. 720h); 0 = never expires")
	return cmd
}

func newTokensListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API tokens (no secrets)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			tokens, err := authn.List(ctx, conn)
			if err != nil {
				return err
			}
			if len(tokens) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no tokens")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tSCOPE\tPREFIX\tCREATED\tEXPIRES\tLAST-USED\tREVOKED")
			for _, t := range tokens {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					t.ID, t.Name, t.Scope, t.Prefix,
					ts(&t.CreatedAt), ts(t.ExpiresAt), ts(t.LastUsedAt), ts(t.RevokedAt))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

func newTokensRevokeCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if err := authn.Revoke(ctx, conn, args[0]); err != nil {
				auditCLI(ctx, conn, "token.revoke", "token", args[0], nil, err)
				return err
			}
			auditCLI(ctx, conn, "token.revoke", "token", args[0], nil, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "token %s revoked\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

// ts renders a nullable timestamp for token listings.
func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format(time.RFC3339)
}
