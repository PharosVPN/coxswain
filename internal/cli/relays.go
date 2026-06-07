// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/server"
	"github.com/PharosVPN/coxswain/internal/ssh"
	"github.com/spf13/cobra"
)

func newRelaysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relays",
		Short: "Enroll and manage relays",
	}
	cmd.AddCommand(
		newRelaysAddCmd(),
		newRelaysListCmd(),
		newRelaysSetEgressCmd(),
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
	var cfgPath, name, endpoint, hostname, user, binaryPath, url, region, srvID string
	var port, egressPort, egressHop, onionPort int
	var egress, onion, noIngress bool
	cmd := &cobra.Command{
		Use:   "add [ssh-host]",
		Short: "Enroll a new relay (onto a server, or directly over SSH)",
		Long: "Deploy a relay. With --server <id>, install onto an already-onboarded\n" +
			"server (the cert hostname defaults to the server's host). Without\n" +
			"--server, connect directly to <ssh-host> over SSH (coxswain's key must\n" +
			"already be on the host). coxswain reaches the relay by dialling out to\n" +
			"its reverse tunnel — no inbound port. A relay on the controller host\n" +
			"(self) is egress/onion only (no client-facing ingress).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			var srv fleet.Server
			if srvID != "" {
				if srv, err = fleet.GetServer(ctx, conn, srvID); err != nil {
					return err
				}
				if hostname == "" {
					hostname = srv.SSHHost
				}
				if region == "" {
					region = srv.Region
				}
				if srv.IsSelf {
					noIngress = true // a relay on the controller host is egress/onion only
				}
			}

			if endpoint == "" && !noIngress {
				return fmt.Errorf("--endpoint is required (the relay's reverse-tunnel address coxswain dials), or pass --no-ingress")
			}
			if hostname == "" {
				hostname = hostOnly(cfg.Relay.PublicEndpoint)
			}
			if hostname == "" {
				return fmt.Errorf("no relay hostname — set relay.public_endpoint or pass --hostname")
			}

			egressEndpoint := ""
			egressHopN := 0
			if egress {
				egressEndpoint = net.JoinHostPort(hostname, strconv.Itoa(egressPort))
				egressHopN = egressHop
				if egressHopN == 0 {
					// Auto-assign the next position after the current last hop.
					relays, lerr := fleet.ListRelays(ctx, conn)
					if lerr != nil {
						return lerr
					}
					for _, r := range relays {
						if r.EgressEndpoint != "" && r.EgressHop > egressHopN {
							egressHopN = r.EgressHop
						}
					}
					egressHopN++
				}
			}

			onionEndpoint := ""
			if onion {
				if !egress {
					return fmt.Errorf("--onion requires --egress (the onion hop reuses the egress chain order)")
				}
				onionEndpoint = net.JoinHostPort(hostname, strconv.Itoa(onionPort))
			}

			spec, err := installSpec(binaryPath, url, cfg.Relay.BinaryURL, "relay.binary_url")
			if err != nil {
				return err
			}
			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			params := deploy.RelayParams{
				Name:           name,
				Region:         region,
				Endpoint:       endpoint,
				Hostname:       hostname,
				EgressEndpoint: egressEndpoint,
				EgressHop:      egressHopN,
				OnionEndpoint:  onionEndpoint,
				NoIngress:      noIngress,
				Install:        spec,
			}

			var res deploy.RelayResult
			if srvID != "" {
				id, _, iErr := ssh.EnsureIdentity(ctx, conn)
				if iErr != nil {
					return iErr
				}
				dialer, dErr := egressDialerForRoute(ctx, conn, srv.Route)
				if dErr != nil {
					return dErr
				}
				res, err = server.DeployRelay(ctx, conn, id, bundle, srv, params, dialer)
			} else {
				if len(args) == 0 {
					return fmt.Errorf("provide an <ssh-host> or --server <id>")
				}
				if user == "" {
					user = cfg.Node.SSHUser
				}
				if port == 0 {
					port = cfg.Node.SSHPort
				}
				host := args[0]
				sshConn, dErr := dialNew(ctx, conn, host, user, port, nil)
				if dErr != nil {
					return dErr
				}
				defer sshConn.Close()
				params.SSHHost, params.SSHUser, params.SSHPort = host, user, port
				res, err = deploy.AddRelay(ctx, conn, sshConn, bundle, params)
			}
			if err != nil {
				auditCLI(ctx, conn, "relay.add", "relay", "", map[string]any{"name": name, "region": region}, err)
				return err
			}
			auditCLI(ctx, conn, "relay.add", "relay", res.Relay.ID, map[string]any{"name": res.Relay.Name, "region": res.Relay.Region}, nil)

			fmt.Printf("relay enrolled — %s\n", res.Relay.Name)
			fmt.Printf("  relay id       %s\n", res.Relay.ID)
			fmt.Printf("  tunnel endpoint %s\n", res.Relay.Endpoint)
			if res.Relay.EgressEndpoint != "" {
				fmt.Printf("  egress endpoint %s (chain hop %d)\n", res.Relay.EgressEndpoint, res.Relay.EgressHop)
			}
			if res.Relay.OnionEndpoint != "" {
				fmt.Printf("  onion endpoint  %s (onion key recorded)\n", res.Relay.OnionEndpoint)
			}
			fmt.Printf("  cert hostname  %s\n", hostname)
			fmt.Printf("  cert serial    %s\n", res.CertSerial)
			fmt.Printf("  relay version %s\n", dash(res.AgentVersion))
			fmt.Printf("  status         %s\n", res.Relay.Status)
			fmt.Println("  cox serve will dial this relay on its next start.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&srvID, "server", "", "deploy onto an onboarded server (see `cox servers list`); hostname/region default to the server's")
	cmd.Flags().StringVar(&name, "name", "", "relay name (generated if empty)")
	cmd.Flags().StringVar(&region, "region", "", "region code for the map (e.g. nyc1)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "the relay's reverse-tunnel address coxswain dials (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "relay cert hostname (defaults to relay.public_endpoint)")
	cmd.Flags().StringVar(&user, "user", "", "SSH user (defaults to node.ssh_user)")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (defaults to node.ssh_port)")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local relay binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the host downloads relay from (overrides config)")
	cmd.Flags().BoolVar(&egress, "egress", false, "also run a control-plane egress relay here, so coxswain reaches nodes through it (decision 19)")
	cmd.Flags().IntVar(&egressPort, "egress-port", 8456, "port the egress relay listens on (coxswain dials hostname:port)")
	cmd.Flags().IntVar(&egressHop, "egress-hop", 0, "explicit chain position (1=closest to coxswain); 0 auto-assigns the next hop")
	cmd.Flags().BoolVar(&onion, "onion", false, "also run an onion hop here (decision 20); requires --egress. coxswain uses onion when every chain relay is onion-capable")
	cmd.Flags().IntVar(&onionPort, "onion-port", 8457, "port the onion relay listens on")
	cmd.Flags().BoolVar(&noIngress, "no-ingress", false, "skip the client-facing ingress relay (egress/onion only) — lets a relay share a host with a node")
	return cmd
}

func newRelaysListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List relays",
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
			fmt.Fprintln(tw, "ID\tNAME\tKIND\tSTATUS\tENDPOINT\tEGRESS\tONION")
			for _, r := range relays {
				egress := "-"
				if r.EgressEndpoint != "" {
					egress = fmt.Sprintf("%s (hop %d)", r.EgressEndpoint, r.EgressHop)
				}
				onion := "-"
				if r.OnionEndpoint != "" && r.OnionPubKey != "" {
					onion = r.OnionEndpoint
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Name, r.Kind, r.Status, dash(r.Endpoint), egress, onion)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newRelaysSetEgressCmd() *cobra.Command {
	var cfgPath string
	var hop int
	var disable bool
	cmd := &cobra.Command{
		Use:   "set-egress <relay-id>",
		Short: "Reorder a relay in the egress chain, or drop it from the chain",
		Long: "Change an enrolled egress relay's position in the control-plane\n" +
			"chain (decision 19), or remove it from the chain. --hop sets the\n" +
			"1-based position (hop 1 is closest to coxswain); --disable drops the\n" +
			"relay from the chain — coxswain stops routing through it on the next\n" +
			"command, though the relay-egress service keeps running on the host\n" +
			"until the operator stops it. Takes effect on coxswain's next dial.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			relay, err := fleet.GetRelay(ctx, conn, args[0])
			if err != nil {
				return err
			}
			switch {
			case disable:
				relay.EgressEndpoint = ""
				relay.EgressHop = 0
			case hop > 0:
				if relay.EgressEndpoint == "" {
					return fmt.Errorf("relay %s is not an egress relay — re-enrol with --egress", relay.ID)
				}
				relay.EgressHop = hop
			default:
				return fmt.Errorf("nothing to do: pass --hop N or --disable")
			}

			updated, err := fleet.UpdateRelay(ctx, conn, relay)
			if err != nil {
				return err
			}
			if updated.EgressEndpoint == "" {
				fmt.Printf("relay %s removed from the egress chain\n", updated.Name)
			} else {
				fmt.Printf("relay %s → egress chain hop %d (%s)\n", updated.Name, updated.EgressHop, updated.EgressEndpoint)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().IntVar(&hop, "hop", 0, "1-based chain position (hop 1 closest to coxswain)")
	cmd.Flags().BoolVar(&disable, "disable", false, "remove this relay from the egress chain")
	return cmd
}

func newRelaysRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "remove <relay-id>",
		Aliases: []string{"rm"},
		Short:   "Remove a relay from the inventory",
		Long: "Remove a relay record. coxswain stops dialling it on the next\n" +
			"`cox serve`. The relay binary keeps running on the host until\n" +
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
