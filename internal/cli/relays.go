// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"net"
	"os"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/spf13/cobra"
)

func newRelaysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relays",
		Short: "Enroll and manage beacon relays",
	}
	cmd.AddCommand(
		newRelaysAddCmd(),
		newRelaysListCmd(),
		newRelaysRemoveCmd(),
	)
	return cmd
}

// hostOnly strips a :port from an address, leaving the host for use as a
// certificate SAN. Inputs without a port are returned unchanged.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func newRelaysAddCmd() *cobra.Command {
	var cfgPath, name, endpoint, hostname, user, binaryPath, url string
	var port int
	cmd := &cobra.Command{
		Use:   "add <ssh-host>",
		Short: "Enroll a new beacon relay over SSH",
		Long: "Enroll a remote beacon relay (BUILD.md \"Relay enrollment\n" +
			"contract\"). coxswain connects to <ssh-host> over SSH, installs the\n" +
			"beacon binary, signs the relay certificate request the binary\n" +
			"generates on the host, pushes the trust material, and starts the\n" +
			"service. coxswain then reaches the relay by dialling out to its\n" +
			"reverse tunnel — no inbound port.\n\n" +
			"Add coxswain's SSH key (see `cox ssh-key`) to the host first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if endpoint == "" {
				return fmt.Errorf("--endpoint is required (the relay's reverse-tunnel address coxswain dials)")
			}
			if hostname == "" {
				hostname = hostOnly(cfg.Beacon.PublicEndpoint)
			}
			if hostname == "" {
				return fmt.Errorf("no relay hostname — set beacon.public_endpoint or pass --hostname")
			}

			spec, err := installSpec(binaryPath, url, cfg.Beacon.BinaryURL, "beacon.binary_url")
			if err != nil {
				return err
			}
			if user == "" {
				user = cfg.Node.SSHUser
			}
			if port == 0 {
				port = cfg.Node.SSHPort
			}

			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			host := args[0]
			sshConn, err := dialNew(ctx, conn, host, user, port)
			if err != nil {
				return err
			}
			defer sshConn.Close()

			res, err := deploy.AddRelay(ctx, conn, sshConn, bundle, deploy.RelayParams{
				Name:     name,
				Endpoint: endpoint,
				Hostname: hostname,
				SSHHost:  host,
				SSHUser:  user,
				SSHPort:  port,
				Install:  spec,
			})
			if err != nil {
				return err
			}

			fmt.Printf("relay enrolled — %s\n", res.Relay.Name)
			fmt.Printf("  relay id       %s\n", res.Relay.ID)
			fmt.Printf("  tunnel endpoint %s\n", res.Relay.Endpoint)
			fmt.Printf("  cert hostname  %s\n", hostname)
			fmt.Printf("  cert serial    %s\n", res.CertSerial)
			fmt.Printf("  beacon version %s\n", dash(res.AgentVersion))
			fmt.Printf("  status         %s\n", res.Relay.Status)
			fmt.Println("  cox serve will dial this relay on its next start.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "relay name (generated if empty)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "the relay's reverse-tunnel address coxswain dials (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "relay cert hostname (defaults to beacon.public_endpoint)")
	cmd.Flags().StringVar(&user, "user", "", "SSH user (defaults to node.ssh_user)")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (defaults to node.ssh_port)")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local beacon binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the host downloads beacon from (overrides config)")
	return cmd
}

func newRelaysListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List beacon relays",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			relays, err := fleet.ListRelays(cmd.Context(), conn)
			if err != nil {
				return err
			}
			if len(relays) == 0 {
				fmt.Println("no relays — run `cox relays add <ssh-host> --endpoint <addr>`")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tKIND\tSTATUS\tENDPOINT")
			for _, r := range relays {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Name, r.Kind, r.Status, dash(r.Endpoint))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newRelaysRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "remove <relay-id>",
		Aliases: []string{"rm"},
		Short:   "Remove a relay from the inventory",
		Long: "Remove a relay record. coxswain stops dialling it on the next\n" +
			"`cox serve`. The beacon binary keeps running on the host until\n" +
			"the operator stops it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if err := fleet.DeleteRelay(cmd.Context(), conn, args[0]); err != nil {
				return err
			}
			fmt.Printf("relay %s removed from inventory\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}
