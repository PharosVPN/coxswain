// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"net"
	"os"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/deviceid"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/spf13/cobra"
)

// newDevicesCmd groups device-identity management. Today it issues the offline
// `.pharosid` bundle a device imports to reach AccountSync through a relay; the
// enrollment-ticket QR (`cox enroll`) is the online counterpart.
func newDevicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage caravel device identities",
	}
	cmd.AddCommand(newDevicesIssueCmd())
	return cmd
}

func newDevicesIssueCmd() *cobra.Command {
	var cfgPath, relay, serverName, out string
	cmd := &cobra.Command{
		Use:   "issue <user-email>",
		Short: "Issue an offline device-identity bundle (.pharosid)",
		Long: "Issue a caravel device a Device-CA mTLS leaf and bundle it with the\n" +
			"relay endpoint and Fleet CA into a .pharosid file. Copy the file to\n" +
			"the device and import it; the device then logs in with the account\n" +
			"passphrase to sync its profile. The file carries a private key — keep\n" +
			"it secret and move it over a trusted channel.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			email := args[0]
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			user, err := account.GetUserByEmail(ctx, conn, email)
			if err != nil {
				return fmt.Errorf("no such user %q: %w", email, err)
			}

			if relay == "" {
				relay = cfg.Relay.PublicEndpoint
			}
			if relay == "" {
				return fmt.Errorf("no relay endpoint — set relay.public_endpoint or pass --relay")
			}
			if serverName == "" {
				if host, _, splitErr := net.SplitHostPort(relay); splitErr == nil {
					serverName = host
				} else {
					serverName = relay
				}
			}

			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			dc, err := pki.IssueDeviceCert(bundle.Device, user.Email)
			if err != nil {
				return fmt.Errorf("issue device cert: %w", err)
			}

			data, err := deviceid.Bundle{
				User:            user.Email,
				RelayAddr:       relay,
				RelayServerName: serverName,
				CAFingerprint:   bundle.Root.Fingerprint(),
				FleetCAPEM:      string(bundle.Fleet.CertPEM),
				DeviceCertPEM:   string(dc.CertPEM),
				DeviceKeyPEM:    string(dc.KeyPEM),
			}.Marshal()
			if err != nil {
				return err
			}

			path := out
			if path == "" {
				path = user.Email + deviceid.Extension
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}

			fmt.Printf("device identity issued for %s\n", user.Email)
			fmt.Printf("  bundle    %s\n", path)
			fmt.Printf("  relay     %s (verify %s)\n", relay, serverName)
			fmt.Printf("  serial    %s\n", dc.Cert.SerialNumber)
			fmt.Printf("  expires   %s\n", dc.Cert.NotAfter.Format("2006-01-02"))
			fmt.Println("  copy this file to the device over a trusted channel — it holds a private key")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&relay, "relay", "", "relay endpoint (defaults to relay.public_endpoint)")
	cmd.Flags().StringVar(&serverName, "server-name", "", "relay cert SAN to verify (defaults to the relay host)")
	cmd.Flags().StringVar(&out, "out", "", "bundle output path (default <email>.pharosid)")
	return cmd
}
