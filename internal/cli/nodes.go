// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/deploy"
	"github.com/PharosVPN/coxswain/internal/fleet"
	buoyv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/buoy/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/wg"
	"github.com/spf13/cobra"
)

// obfNote describes whether a node also reported obfuscation parameters, for
// the `nodes status` summary line.
func obfNote(o wg.Obfuscation) string {
	if o.IsZero() {
		return " (obfuscation not reported)"
	}
	return " + obfuscation"
}

// controlRPCTimeout bounds a single control-plane RPC.
const controlRPCTimeout = 10 * time.Second

func newNodesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "Onboard and manage buoy fleet nodes",
	}
	cmd.AddCommand(
		newNodesAddCmd(),
		newNodesListCmd(),
		newNodesStatusCmd(),
		newNodesPushCmd(),
		newNodesPushPolicyCmd(),
		newNodesUpdateCmd(),
		newNodesStartCmd(),
		newNodesStopCmd(),
		newNodesRemoveCmd(),
	)
	return cmd
}

func newNodesStatusCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "status <node-id>",
		Short: "Query a node's live status over the gRPC control plane",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			node, err := fleet.GetNode(ctx, conn, args[0])
			if err != nil {
				return err
			}
			if node.ControlAddr == "" {
				return fmt.Errorf("node %s has no control address", node.ID)
			}

			dialer, err := newControlDialer(ctx, conn)
			if err != nil {
				return err
			}
			client, err := dialer.Dial(node.ControlAddr)
			if err != nil {
				return err
			}
			defer client.Close()

			rpcCtx, cancel := context.WithTimeout(ctx, controlRPCTimeout)
			defer cancel()
			status, err := client.Status(rpcCtx)
			if err != nil {
				return fmt.Errorf("control %s: %w", node.ControlAddr, err)
			}

			fmt.Printf("node %s — live status\n", node.Name)
			fmt.Printf("  agent version %s\n", dash(status.GetAgentVersion()))
			fmt.Printf("  uptime        %ds\n", status.GetUptimeSeconds())
			if len(status.GetServices()) == 0 {
				fmt.Println("  services      (none reported)")
				return nil
			}
			fmt.Println("  services:")
			for _, svc := range status.GetServices() {
				proto := strings.TrimPrefix(svc.GetProtocol().String(), "PROTOCOL_")
				fmt.Printf("    %-14s running=%t listening=%t peers=%d\n",
					proto, svc.GetRunning(), svc.GetListening(), svc.GetPeerCount())
			}

			// Persist the AmneziaWG identity buoy reports — its public key and
			// per-node obfuscation. Provisioning needs both before it can place
			// a device on the node (DESIGN §3).
			if pubKey, obf := control.AmneziaWGFromStatus(status); pubKey != "" {
				if err := fleet.SetNodeAmneziaWG(ctx, conn, node.ID, pubKey, obf); err != nil {
					return fmt.Errorf("record amneziawg identity: %w", err)
				}
				fmt.Printf("  amneziawg     public key recorded%s\n", obfNote(obf))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

// installSpec resolves how to install an agent binary from the CLI flags.
// configHint names the config key that supplies a default URL.
func installSpec(binaryPath, url, defaultURL, configHint string) (deploy.InstallSpec, error) {
	if binaryPath != "" {
		data, err := os.ReadFile(binaryPath)
		if err != nil {
			return deploy.InstallSpec{}, fmt.Errorf("read binary: %w", err)
		}
		return deploy.InstallSpec{Binary: data}, nil
	}
	if url == "" {
		url = defaultURL
	}
	if url == "" {
		return deploy.InstallSpec{}, fmt.Errorf(
			"provide --binary, --url, or set %s in the config", configHint)
	}
	return deploy.InstallSpec{URL: url}, nil
}

func newNodesAddCmd() *cobra.Command {
	var cfgPath, region, name, user, binaryPath, url string
	var port int
	cmd := &cobra.Command{
		Use:   "add <ssh-host>",
		Short: "Onboard a new buoy node over SSH",
		Long: "Onboard a buoy node (DESIGN §5). coxswain connects to <ssh-host>\n" +
			"over SSH, installs the buoy agent, signs the certificate request\n" +
			"the agent generates on the node, and starts the service.\n\n" +
			"Add coxswain's SSH key (see `cox ssh-key`) to the host first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			spec, err := installSpec(binaryPath, url, cfg.Node.BuoyBinaryURL, "node.buoy_binary_url")
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

			res, err := deploy.AddNode(ctx, conn, sshConn, bundle, deploy.AddParams{
				Name:    name,
				Region:  region,
				SSHHost: host,
				SSHUser: user,
				SSHPort: port,
				Install: spec,
			})
			if err != nil {
				return err
			}

			fmt.Printf("node onboarded — %s\n", res.Node.Name)
			fmt.Printf("  node id       %s\n", res.Node.ID)
			fmt.Printf("  region        %s\n", res.Node.Region)
			fmt.Printf("  ssh           %s@%s:%d\n", res.Node.SSHUser, res.Node.SSHHost, res.Node.SSHPort)
			fmt.Printf("  control addr  %s\n", res.Node.ControlAddr)
			fmt.Printf("  agent version %s\n", dash(res.AgentVersion))
			fmt.Printf("  node cert     %s\n", res.NodeCertID)
			fmt.Printf("  status        %s\n", res.Node.Status)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&region, "region", "", "region label for the node (required)")
	cmd.Flags().StringVar(&name, "name", "", "node name (generated from the region if empty)")
	cmd.Flags().StringVar(&user, "user", "", "SSH user (defaults to node.ssh_user)")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (defaults to node.ssh_port)")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local buoy binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the node downloads buoy from (overrides config)")
	_ = cmd.MarkFlagRequired("region")
	return cmd
}

func newNodesListCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List fleet nodes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			nodes, err := fleet.ListNodes(cmd.Context(), conn)
			if err != nil {
				return err
			}
			if len(nodes) == 0 {
				fmt.Println("no nodes — run `cox nodes add <ssh-host> --region <region>`")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tREGION\tSTATUS\tSSH HOST\tAGENT")
			for _, n := range nodes {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					n.ID, n.Name, n.Region, n.Status, dash(n.SSHHost), dash(n.AgentVersion))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

// toBuoyAmneziaWGPeers converts coxswain's fleet.Peer rows for one node into the
// proto Peer messages PushAmneziaWGConfig expects. Non-AmneziaWG peers are
// skipped — XRay lands in B3 with its own encoder.
func toBuoyAmneziaWGPeers(peers []fleet.Peer) []*buoyv1.Peer {
	out := make([]*buoyv1.Peer, 0, len(peers))
	for _, p := range peers {
		if p.Protocol != profile.ProtocolAmneziaWG {
			continue
		}
		out = append(out, &buoyv1.Peer{
			Id:           p.ID,
			Protocol:     buoyv1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    p.PublicKey,
			AllowedIps:   []string{p.AllowedIP},
			PresharedKey: p.PresharedKey,
		})
	}
	return out
}

func newNodesPushCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "push <node-id>",
		Short: "Push the current peer set to a node's AmneziaWG data plane",
		Long: "Reconcile a node by pushing coxswain's current AmneziaWG peer set\n" +
			"over the control channel (PushConfig — full-replace). buoy bumps\n" +
			"awg0 in place, no tunnel drops. coxswain assigns a monotonic revision\n" +
			"per node; buoy rejects stale revisions with FailedPrecondition.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			node, err := fleet.GetNode(ctx, conn, args[0])
			if err != nil {
				return err
			}
			if node.ControlAddr == "" {
				return fmt.Errorf("node %s has no control address", node.ID)
			}

			peers, err := fleet.ListPeersByNode(ctx, conn, node.ID)
			if err != nil {
				return err
			}
			amneziaPeers := toBuoyAmneziaWGPeers(peers)

			dialer, err := newControlDialer(ctx, conn)
			if err != nil {
				return err
			}
			client, err := dialer.Dial(node.ControlAddr)
			if err != nil {
				return err
			}
			defer client.Close()

			revision, err := fleet.NextNodeConfigRevision(ctx, conn, node.ID)
			if err != nil {
				return err
			}

			rpcCtx, cancel := context.WithTimeout(ctx, controlRPCTimeout)
			defer cancel()
			resp, err := client.PushAmneziaWGConfig(rpcCtx, revision, amneziaPeers)
			if err != nil {
				return fmt.Errorf("control %s: %w", node.ControlAddr, err)
			}

			fmt.Printf("node %s — pushed %d AmneziaWG peer(s)\n", node.Name, len(amneziaPeers))
			fmt.Printf("  revision  %d (applied %d)\n", revision, resp.GetAppliedRevision())
			fmt.Printf("  reloaded  %t\n", resp.GetReloaded())
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newNodesPushPolicyCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "push-policy <node-id>",
		Short: "Push the node's network policy over the control channel",
		Long: "Apply the node's stored forwarding / masquerade / isolation\n" +
			"policy (DESIGN §3, decision 16) to its data plane via\n" +
			"SetNetworkConfig. Run this after editing policy in the admin UI\n" +
			"or `cox nodes update` to make the new rules take effect.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			node, err := fleet.GetNode(ctx, conn, args[0])
			if err != nil {
				return err
			}
			if node.ControlAddr == "" {
				return fmt.Errorf("node %s has no control address", node.ID)
			}

			dialer, err := newControlDialer(ctx, conn)
			if err != nil {
				return err
			}
			client, err := dialer.Dial(node.ControlAddr)
			if err != nil {
				return err
			}
			defer client.Close()

			rpcCtx, cancel := context.WithTimeout(ctx, controlRPCTimeout)
			defer cancel()
			resp, err := client.SetNetworkConfig(rpcCtx, node.Forwarding, node.Masquerade, node.Isolation, nil)
			if err != nil {
				return fmt.Errorf("control %s: %w", node.ControlAddr, err)
			}

			fmt.Printf("node %s — network policy pushed\n", node.Name)
			fmt.Printf("  forwarding %t  masquerade %t  isolation %t\n",
				node.Forwarding, node.Masquerade, node.Isolation)
			fmt.Printf("  applied    %t\n", resp.GetApplied())
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newNodesUpdateCmd() *cobra.Command {
	var cfgPath, binaryPath, url string
	cmd := &cobra.Command{
		Use:   "update <node-id>",
		Short: "Re-deploy the buoy agent on a node over SSH",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			node, err := fleet.GetNode(ctx, conn, args[0])
			if err != nil {
				return err
			}
			spec, err := installSpec(binaryPath, url, cfg.Node.BuoyBinaryURL, "node.buoy_binary_url")
			if err != nil {
				return err
			}

			sshConn, err := dialNode(ctx, conn, node)
			if err != nil {
				return err
			}
			defer sshConn.Close()

			updated, err := deploy.UpdateAgent(ctx, conn, sshConn, node, spec)
			if err != nil {
				return err
			}
			fmt.Printf("node %s updated — agent version %s\n", updated.ID, dash(updated.AgentVersion))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local buoy binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the node downloads buoy from (overrides config)")
	return cmd
}

func newNodesStartCmd() *cobra.Command {
	return newNodesPowerCmd("start", "Start the buoy service on a node", fleet.StatusActive)
}

func newNodesStopCmd() *cobra.Command {
	return newNodesPowerCmd("stop", "Stop the buoy service on a node", fleet.StatusStopped)
}

// newNodesPowerCmd builds the shared start/stop command. It controls the buoy
// service on the node over SSH — the VM itself is left running.
func newNodesPowerCmd(verb, short, newStatus string) *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   verb + " <node-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			node, err := fleet.GetNode(ctx, conn, args[0])
			if err != nil {
				return err
			}
			sshConn, err := dialNode(ctx, conn, node)
			if err != nil {
				return err
			}
			defer sshConn.Close()

			if err := deploy.Service(ctx, sshConn, verb); err != nil {
				return err
			}
			node.Status = newStatus
			if _, err := fleet.UpdateNode(ctx, conn, node); err != nil {
				return err
			}
			fmt.Printf("node %s: buoy service %sped — status %s\n", node.ID, verb, newStatus)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func newNodesRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "remove <node-id>",
		Aliases: []string{"rm"},
		Short:   "Remove a node from the fleet inventory",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			if err := fleet.DeleteNode(cmd.Context(), conn, args[0]); err != nil {
				return err
			}
			fmt.Printf("node %s removed from inventory\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
