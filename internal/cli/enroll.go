// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"os"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/enroll"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/spf13/cobra"
)

func newEnrollCmd() *cobra.Command {
	var cfgPath, relay, out string
	cmd := &cobra.Command{
		Use:   "enroll <user-id>",
		Short: "Issue a device-enrollment QR for a user",
		Long: "Issue a one-time enrollment ticket and render it as a QR code\n" +
			"(DESIGN §9). The user scans it with caravel to enrol a device and\n" +
			"pull their profile. The ticket carries the relay endpoint, a\n" +
			"one-time claim token, and the CA fingerprint to pin.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID := args[0]
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if _, err := account.GetUser(ctx, conn, userID); err != nil {
				return err
			}
			if relay == "" {
				relay = cfg.Beacon.PublicEndpoint
			}
			if relay == "" {
				return fmt.Errorf("no relay endpoint — set beacon.public_endpoint or pass --relay")
			}

			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			ticket, token, err := enroll.IssueTicket(ctx, conn, userID)
			if err != nil {
				return err
			}
			link := enroll.TicketURL(relay, token, bundle.Root.Fingerprint())
			png, err := enroll.QRCode(link)
			if err != nil {
				return err
			}

			path := out
			if path == "" {
				path = userID + "-enroll.png"
			}
			if err := os.WriteFile(path, png, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}

			fmt.Printf("enrollment ticket issued for %s\n", userID)
			fmt.Printf("  ticket    %s\n", ticket.ID)
			fmt.Printf("  QR        %s\n", path)
			fmt.Printf("  link      %s\n", link)
			fmt.Printf("  expires   %s (one-time)\n", enroll.TicketTTL)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&relay, "relay", "", "relay endpoint (defaults to beacon.public_endpoint)")
	cmd.Flags().StringVar(&out, "out", "", "QR output path (default <user-id>-enroll.png)")
	return cmd
}
