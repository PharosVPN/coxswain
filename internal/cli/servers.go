// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/server"
	"github.com/PharosVPN/coxswain/internal/ssh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newServersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "servers",
		Short: "Onboard and manage servers (machines cox owns)",
	}
	cmd.AddCommand(newServersAddCmd(), newServersListCmd(), newServersSelfCmd(), newServersRemoveCmd())
	return cmd
}

func newServersAddCmd() *cobra.Command {
	var cfgPath, name, region, user, password, via string
	var port int
	var useKey bool
	cmd := &cobra.Command{
		Use:   "add <ip>",
		Short: "Onboard a server by key or one-time password (cox installs its SSH key)",
		Long: "Onboard a raw machine, by one of two methods:\n\n" +
			"  --key       coxswain's SSH key is already on the host (e.g. you added\n" +
			"              it as the droplet's login key at creation; see `cox ssh-key`)\n" +
			"  --password  coxswain logs in with the one-time password, installs its\n" +
			"  (or prompt) key, then switches to key auth. The password is never stored.\n\n" +
			"Then deploy node/relay roles with `cox nodes add --server <id>` /\n" +
			"`cox relays add --server <id>`. The region is resolved from the IP.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if user == "" {
				user = cfg.Node.SSHUser
			}
			if user == "" {
				user = "root"
			}
			if port == 0 {
				port = cfg.Node.SSHPort
			}
			if !useKey {
				if password == "" {
					password, err = promptPassword(fmt.Sprintf("SSH password for %s@%s: ", user, args[0]))
					if err != nil {
						return err
					}
				}
				if password == "" {
					return fmt.Errorf("provide a password (--password or prompt), or use --key if coxswain's key is already on the host")
				}
			}

			id, _, err := ssh.EnsureIdentity(ctx, conn)
			if err != nil {
				return err
			}
			// Direct by default; --via routes the onboard (and this server's later
			// deploy/RPC dials) through the named relay hops.
			route := splitCSV(via)
			dialer, err := egressDialerForRoute(ctx, conn, route)
			if err != nil {
				return err
			}

			srv, err := server.Bootstrap(ctx, conn, id, server.BootstrapParams{
				Name:     name,
				Region:   region,
				Host:     args[0],
				User:     user,
				Port:     port,
				Password: password,
				Route:    route,
				Dialer:   dialer,
			})
			if err != nil {
				auditCLI(ctx, conn, "server.add", "server", "", map[string]any{"ssh_host": args[0]}, err)
				return err
			}
			auditCLI(ctx, conn, "server.add", "server", srv.ID, map[string]any{"name": srv.Name, "ssh_host": srv.SSHHost}, nil)

			fmt.Printf("server onboarded — %s\n", dash(srv.Name))
			fmt.Printf("  server id   %s\n", srv.ID)
			fmt.Printf("  ssh         %s@%s:%d\n", srv.SSHUser, srv.SSHHost, srv.SSHPort)
			fmt.Printf("  region      %s\n", dash(srv.Region))
			fmt.Printf("  route       %s\n", routeLabel(srv.Route))
			fmt.Printf("  status      %s\n", srv.Status)
			fmt.Printf("  cox's SSH key is installed; deploy a role with `cox nodes add --server %s`\n", srv.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "server name (defaults to the IP)")
	cmd.Flags().StringVar(&region, "region", "", "region label for the map")
	cmd.Flags().StringVar(&user, "user", "", "SSH user (defaults to node.ssh_user, then root)")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (defaults to node.ssh_port)")
	cmd.Flags().StringVar(&password, "password", "", "one-time SSH password (prompted if omitted; never stored)")
	cmd.Flags().BoolVar(&useKey, "key", false, "use coxswain's SSH key (already installed on the host) instead of a password")
	cmd.Flags().StringVar(&via, "via", "", "ordered relay-id hops to route this server through, comma-separated (empty = direct)")
	return cmd
}

// routeLabel renders a server's provision route for CLI output.
func routeLabel(route []string) string {
	if len(route) == 0 {
		return "direct"
	}
	return "via " + strings.Join(route, " → ")
}

func newServersListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List onboarded servers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			servers, err := fleet.ListServers(ctx, conn)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tREGION\tSTATUS\tSSH-HOST\tROUTE\tSELF")
			for _, s := range servers {
				self := ""
				if s.IsSelf {
					self = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.ID, dash(s.Name), dash(s.Region), s.Status, dash(s.SSHHost), routeLabel(s.Route), self)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newServersSelfCmd() *cobra.Command {
	var cfgPath, host string
	cmd := &cobra.Command{
		Use:   "self",
		Short: "Register/refresh the controller's own host as a server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if host != "" {
				cfg.Relay.PublicEndpoint = host // force selfHost to this value
			}
			srv, err := ensureSelfServer(ctx, conn, cfg)
			if err != nil {
				return err
			}
			fmt.Printf("self server %s — %s (%s)\n", srv.ID, dash(srv.SSHHost), srv.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&host, "host", "", "controller host address (defaults to relay.public_endpoint or autodetected)")
	return cmd
}

func newServersRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "rm <server-id>",
		Aliases: []string{"remove"},
		Short:   "Remove a server from the inventory (must have no deployed roles)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := fleet.DeleteServer(ctx, conn, args[0]); err != nil {
				auditCLI(ctx, conn, "server.rm", "server", args[0], nil, err)
				if errors.Is(err, fleet.ErrServerInUse) {
					return fmt.Errorf("server %s still has node/relay roles deployed — remove those first", args[0])
				}
				return err
			}
			auditCLI(ctx, conn, "server.rm", "server", args[0], nil, nil)
			fmt.Printf("server %s removed\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

// ensureSelfServer registers the controller's own host as the single is_self
// server if not already present, and returns it. Idempotent.
func ensureSelfServer(ctx context.Context, conn *sql.DB, cfg config.Config) (fleet.Server, error) {
	if s, err := fleet.GetSelfServer(ctx, conn); err == nil {
		return s, nil
	} else if !errors.Is(err, fleet.ErrNotFound) {
		return fleet.Server{}, err
	}
	user := cfg.Node.SSHUser
	if user == "" {
		user = "root"
	}
	return fleet.CreateServer(ctx, conn, fleet.Server{
		Name:    "controller",
		IsSelf:  true,
		SSHHost: selfHost(cfg),
		SSHUser: user,
		Status:  fleet.StatusActive,
	})
}

// selfHost is the controller host's address: the configured public endpoint if
// set, else the first non-loopback outbound IP, else "localhost". It becomes the
// self server's address (and any self-deployed node's cert SAN / control addr).
func selfHost(cfg config.Config) string {
	if cfg.Relay.PublicEndpoint != "" {
		return hostOnly(cfg.Relay.PublicEndpoint)
	}
	if ip := outboundIP(); ip != "" {
		return ip
	}
	return "localhost"
}

// outboundIP returns the local address the kernel would use to reach the public
// internet, without sending anything (UDP "connect" only sets the route).
func outboundIP() string {
	c, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return ""
}

// promptPassword reads a password from the terminal without echoing it.
func promptPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no terminal to prompt for a password; pass --password")
	}
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pw), nil
}
