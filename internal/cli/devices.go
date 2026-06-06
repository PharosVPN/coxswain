// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/deviceid"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"github.com/spf13/cobra"
)

// newDevicesCmd groups device-identity management. `issue` enrolls and provisions
// a named device and writes the offline `.pharosid` bundle the device imports to
// sync its own profile through a relay; `cox enroll` is the online QR counterpart.
func newDevicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage caravel device identities",
	}
	cmd.AddCommand(newDevicesIssueCmd())
	return cmd
}

func newDevicesIssueCmd() *cobra.Command {
	var cfgPath, relay, serverName, out, name, pathID string
	cmd := &cobra.Command{
		Use:   "issue <user-email>",
		Short: "Enrol + provision a device and write its .pharosid bundle",
		Long: "Create a named device for a user, give it a Device-CA mTLS leaf,\n" +
			"provision it (its own WireGuard keypair, tunnel IP, node peers, and\n" +
			"egress path), and bundle the leaf + relay endpoint + Fleet CA into a\n" +
			".pharosid file. Copy the file to the device and import it; the device\n" +
			"logs in with the account passphrase to sync *its own* profile.\n\n" +
			"The user must have an enrolled encryption key (set up on a first device).\n" +
			"After issuing, run `cox nodes push <node>` so the new device's peer\n" +
			"reaches the nodes. The file holds a private key — move it secretly.",
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
			if name == "" {
				name = "caravel device"
			}

			bundle, _, err := pki.EnsureCA(ctx, conn)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			dc, err := pki.IssueDeviceCert(bundle.Device, user.Email)
			if err != nil {
				return fmt.Errorf("issue device cert: %w", err)
			}

			// Create the device, keyed to the leaf's fingerprint — the same value
			// the relay forwards (x-pharos-device-fp) so account sync can identify it.
			device, err := account.CreateDevice(ctx, conn, account.Device{
				UserID:      user.ID,
				Name:        name,
				Platform:    "caravel",
				Fingerprint: deviceFingerprint(dc.Cert.Raw),
			})
			if err != nil {
				return fmt.Errorf("create device: %w", err)
			}

			// Optionally bind the device to a cascade path before provisioning, so
			// its sealed profile carries the egress chain.
			if pathID != "" {
				if _, err := fleet.GetPath(ctx, conn, pathID); err != nil {
					return fmt.Errorf("no such path %q: %w", pathID, err)
				}
				if err := fleet.SetDeviceExit(ctx, conn, device.ID, pathID); err != nil {
					return fmt.Errorf("bind path: %w", err)
				}
			}

			// Provision: the device's own WG keypair + tunnel IP + per-node peers,
			// sealed into its own profile.
			res, err := provision.ProvisionDevice(ctx, conn, device.ID, provision.Options{
				VPNSubnet: cfg.Fleet.VPNSubnet,
				PortMin:   cfg.Fleet.EndpointPortMin,
				PortMax:   cfg.Fleet.EndpointPortMax,
				Rotation: profile.RotationPolicy{
					Enabled:         cfg.Fleet.Rotation.Enabled,
					IntervalSeconds: cfg.Fleet.Rotation.IntervalSeconds,
					JitterSeconds:   cfg.Fleet.Rotation.JitterSeconds,
				},
				XRay: provision.XRayOptions{
					Enabled:    cfg.Protocols.XRay,
					ServerName: cfg.Reality.DecoySite,
				},
			})
			if errors.Is(err, profile.ErrNoEncryptionKey) {
				return fmt.Errorf("user %s has not enrolled an encryption key yet — set up a first device and sync once to enroll, then re-issue", user.Email)
			}
			if err != nil {
				return fmt.Errorf("provision device: %w", err)
			}

			data, err := deviceid.Bundle{
				User:            user.Email,
				Alias:           name,
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

			fmt.Printf("device %q provisioned for %s\n", name, user.Email)
			fmt.Printf("  device id   %s\n", device.ID)
			fmt.Printf("  bundle      %s\n", path)
			fmt.Printf("  relay       %s (verify %s)\n", relay, serverName)
			fmt.Printf("  tunnel ip   %s · %d peer(s) · profile rev %d\n", res.TunnelIP, res.PeerCount, res.ProfileVersion)
			if pathID != "" {
				fmt.Printf("  egress path %s\n", pathID)
			}
			fmt.Println("  next: run `cox nodes push <node>` so the device's peer reaches the nodes")
			fmt.Println("  copy the .pharosid to the device over a trusted channel — it holds a private key")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&name, "name", "", "device alias / friendly name (default \"caravel device\")")
	cmd.Flags().StringVar(&pathID, "path", "", "bind the device to this cascade path id (egress chain)")
	cmd.Flags().StringVar(&relay, "relay", "", "relay endpoint (defaults to relay.public_endpoint)")
	cmd.Flags().StringVar(&serverName, "server-name", "", "relay cert SAN to verify (defaults to the relay host)")
	cmd.Flags().StringVar(&out, "out", "", "bundle output path (default <email>.pharosid)")
	return cmd
}

// deviceFingerprint computes the device-leaf fingerprint coxswain stores and the
// relay forwards: sha256 of the PEM-encoded certificate, hex, "sha256:"-prefixed
// (must match relay/core.certFingerprint byte-for-byte).
func deviceFingerprint(der []byte) string {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	h := sha256.Sum256(pemBytes)
	return "sha256:" + hex.EncodeToString(h[:])
}
