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
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/reconcile"
	"github.com/PharosVPN/coxswain/internal/server"
	"github.com/PharosVPN/coxswain/internal/ssh"
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
		Short: "Onboard and manage fleet nodes",
	}
	cmd.AddCommand(
		newNodesAddCmd(),
		newNodesListCmd(),
		newNodesStatusCmd(),
		newNodesPushCmd(),
		newNodesPushPolicyCmd(),
		newNodesEndpointsCmd(),
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

			dialer, err := newControlDialer(ctx, conn, nodeRoute(ctx, conn, node))
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
				line := fmt.Sprintf("    %-14s running=%t listening=%t peers=%d",
					proto, svc.GetRunning(), svc.GetListening(), svc.GetPeerCount())
				// Handshake liveness (AmneziaWG only; age=-1 means n/a). A peer set
				// with zero recent handshakes is a stale/broken data plane even when
				// it reports running+listening — the silent-drift signature.
				if age := svc.GetNewestHandshakeAgeSeconds(); age >= 0 {
					line += fmt.Sprintf(" handshaking=%d/%d newest=%s",
						svc.GetHandshakingPeers(), svc.GetPeerCount(),
						(time.Duration(age) * time.Second).String())
					if svc.GetPeerCount() > 0 && svc.GetHandshakingPeers() == 0 {
						line += "  ⚠ STALE — peers but no handshakes"
					}
				}
				fmt.Println(line)
			}

			// Config revision: what the node has actually applied vs what coxswain
			// intends. A node behind its intended revision is serving a stale peer
			// set (heal with `cox nodes push <id>`). (Provision advances intent in
			// Phase 2; until then this catches push-rejected / never-applied cases.)
			applied, intended := status.GetAppliedRevision(), node.ConfigRevision
			fmt.Printf("  revision      applied=%d intended=%d", applied, intended)
			if applied < intended {
				fmt.Printf("  ⚠ DRIFT — node behind; run `cox nodes push %s`", node.ID)
			}
			fmt.Println()

			// Persist the AmneziaWG identity node reports — its public key and
			// per-node obfuscation. Provisioning needs both before it can place
			// a device on the node (DESIGN §3).
			if pubKey, obf := control.AmneziaWGFromStatus(status); pubKey != "" {
				if err := fleet.SetNodeAmneziaWG(ctx, conn, node.ID, pubKey, obf); err != nil {
					return fmt.Errorf("record amneziawg identity: %w", err)
				}
				fmt.Printf("  amneziawg     public key recorded%s\n", obfNote(obf))
			}
			// Persist the XRay/REALITY public key node reports, so provisioning can
			// place a REALITY client on the node (DESIGN §3, §12).
			if xpk := control.XRayFromStatus(status); xpk != "" {
				if err := fleet.SetNodeXRayReality(ctx, conn, node.ID, xpk); err != nil {
					return fmt.Errorf("record xray reality identity: %w", err)
				}
				fmt.Println("  xray-reality  public key recorded")
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
	var cfgPath, region, name, user, binaryPath, url, srvID string
	var port int
	cmd := &cobra.Command{
		Use:   "add [ssh-host]",
		Short: "Onboard a new node (onto a server, or directly over SSH)",
		Long: "Deploy a node. With --server <id>, install onto an already-onboarded\n" +
			"server (no SSH key setup needed — `cox servers add` did that). Without\n" +
			"--server, connect directly to <ssh-host> over SSH (coxswain's key must\n" +
			"already be on the host — see `cox ssh-key`).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			spec, err := installSpec(binaryPath, url, cfg.Node.NodeBinaryURL, "node.node_binary_url")
			if err != nil {
				return err
			}
			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}

			var res deploy.AddResult
			if srvID != "" {
				// Deploy onto an onboarded server (reuses its key access).
				srv, gErr := fleet.GetServer(ctx, conn, srvID)
				if gErr != nil {
					return gErr
				}
				id, _, iErr := ssh.EnsureIdentity(ctx, conn)
				if iErr != nil {
					return iErr
				}
				dialer, dErr := egressDialerForRoute(ctx, conn, srv.Route)
				if dErr != nil {
					return dErr
				}
				res, err = server.DeployNode(ctx, conn, id, bundle, srv,
					deploy.AddParams{Name: name, Region: region, Install: spec}, dialer)
			} else {
				// Direct SSH (coxswain's key must be pre-installed).
				if len(args) == 0 {
					return fmt.Errorf("provide an <ssh-host> or --server <id>")
				}
				if region == "" {
					return fmt.Errorf("--region is required when onboarding by ssh-host")
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
				res, err = deploy.AddNode(ctx, conn, sshConn, bundle, deploy.AddParams{
					Name:    name,
					Region:  region,
					SSHHost: host,
					SSHUser: user,
					SSHPort: port,
					Install: spec,
				})
			}
			if err != nil {
				auditCLI(ctx, conn, "node.add", "node", "", map[string]any{"name": name, "region": region}, err)
				return err
			}
			auditCLI(ctx, conn, "node.add", "node", res.Node.ID, map[string]any{"name": res.Node.Name, "region": res.Node.Region}, nil)

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
	cmd.Flags().StringVar(&srvID, "server", "", "deploy onto an onboarded server (see `cox servers list`); region defaults to the server's")
	cmd.Flags().StringVar(&region, "region", "", "region label for the node (required without --server)")
	cmd.Flags().StringVar(&name, "name", "", "node name (generated from the region if empty)")
	cmd.Flags().StringVar(&user, "user", "", "SSH user (defaults to node.ssh_user; ignored with --server)")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port (defaults to node.ssh_port; ignored with --server)")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local node binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the node downloads node from (overrides config)")
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

func newNodesPushCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "push <node-id>",
		Short: "Push the current peer set to a node's data plane",
		Long: "Reconcile a node by pushing coxswain's current peer set over the\n" +
			"control channel (PushConfig — full-replace). The AmneziaWG peer set\n" +
			"always pushes; the XRay/REALITY set + camouflage policy also push when\n" +
			"protocols.xray is enabled. node bumps each data plane in place, no\n" +
			"tunnel drops. coxswain assigns a monotonic revision per push; node\n" +
			"rejects stale revisions with FailedPrecondition.",
		Args: cobra.ExactArgs(1),
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

			// PushNode is the single delivery primitive (Phase 2) — the same flow
			// this command used to inline, now shared with provisioning, the sweep,
			// and the API.
			res, err := reconcile.PushNode(ctx, &cfg, conn, node)
			if err != nil {
				return err
			}

			fmt.Printf("node %s — pushed %d AmneziaWG peer(s)\n", node.Name, res.AmneziaPeers)
			fmt.Printf("  revision  %d (applied %d)\n", res.PushedRevision, res.AppliedRevision)
			fmt.Printf("  reloaded  %t\n", res.Reloaded)
			if cfg.Protocols.XRay {
				if res.XRaySkipped {
					fmt.Println("  xray      skipped (node has no REALITY support)")
				} else {
					fmt.Printf("  xray      pushed %d REALITY client(s)\n", res.XRayPeers)
				}
			}
			if res.CascadeReapplied {
				fmt.Println("  cascade   edge peers re-applied")
			}
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

			dialer, err := newControlDialer(ctx, conn, nodeRoute(ctx, conn, node))
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

func newNodesEndpointsCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "endpoints <node-id> [ip,ip,...]",
		Short: "Show or set a node's entry IP pool (decision 17)",
		Long: "Show a node's AmneziaWG endpoint IP pool, or set it to a comma-separated\n" +
			"IP list. Clients pick a RANDOM IP from the pool on each connect, so the\n" +
			"entry point varies — nothing fixed to fingerprint or block. The IPs must\n" +
			"already reach the node (its primary IP plus any reserved/floating IPs you\n" +
			"have attached). Pass \"\" to clear the pool (falls back to the public IP).\n" +
			"New profiles carry the pool; re-provision a device to pick up a change.",
		Args: cobra.RangeArgs(1, 2),
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
			if len(args) == 2 {
				var ips []string
				if strings.TrimSpace(args[1]) != "" {
					ips = strings.Split(args[1], ",")
				}
				if err := fleet.SetNodeEndpoints(ctx, conn, node.ID, ips); err != nil {
					return err
				}
				if node, err = fleet.GetNode(ctx, conn, node.ID); err != nil {
					return err
				}
				fmt.Printf("node %s — entry pool set\n", node.Name)
			}
			fmt.Printf("node %s (%s)\n", node.Name, node.Region)
			fmt.Printf("  public ip   %s\n", node.PublicIP)
			fmt.Printf("  entry pool  %s\n", strings.Join(node.EndpointAddrs(), ", "))
			if len(node.EndpointIPs) == 0 {
				fmt.Println("              (default: public IP only — set a pool to randomize entry)")
			}
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
		Short: "Re-deploy the node agent on a node over SSH",
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
			spec, err := installSpec(binaryPath, url, cfg.Node.NodeBinaryURL, "node.node_binary_url")
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
				auditCLI(ctx, conn, "node.update", "node", node.ID, map[string]any{"name": node.Name}, err)
				return err
			}
			auditCLI(ctx, conn, "node.update", "node", updated.ID, map[string]any{"name": updated.Name, "agent_version": updated.AgentVersion}, nil)
			fmt.Printf("node %s updated — agent version %s\n", updated.ID, dash(updated.AgentVersion))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&binaryPath, "binary", "", "path to a local node binary to upload")
	cmd.Flags().StringVar(&url, "url", "", "URL the node downloads node from (overrides config)")
	return cmd
}

func newNodesStartCmd() *cobra.Command {
	return newNodesPowerCmd("start", "Start the node service on a node", fleet.StatusActive)
}

func newNodesStopCmd() *cobra.Command {
	return newNodesPowerCmd("stop", "Stop the node service on a node", fleet.StatusStopped)
}

// newNodesPowerCmd builds the shared start/stop command. It controls the node
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
			fmt.Printf("node %s: node service %sped — status %s\n", node.ID, verb, newStatus)
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
				auditCLI(cmd.Context(), conn, "node.rm", "node", args[0], nil, err)
				return err
			}
			auditCLI(cmd.Context(), conn, "node.rm", "node", args[0], nil, nil)
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
