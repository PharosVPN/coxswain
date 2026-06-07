// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"github.com/PharosVPN/coxswain/internal/reconcile"
	"github.com/spf13/cobra"
)

// newProfilesCmd manages profiles — the admin-created connection configs a
// device holds. A profile names an egress (a single node for a direct exit, or
// a multi-hop path), an optional subset of the entry node's IP pool, and one
// data-plane protocol. A device may have several; the device syncs and the
// caravel app lists them by name. (Distinct from `cox profile export`, which
// writes a device's sealed bundle.)
func newProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Manage profiles (a device's named connection configs)",
	}
	cmd.AddCommand(
		newProfilesCreateCmd(),
		newProfilesListCmd(),
		newProfilesRemoveCmd(),
	)
	return cmd
}

func newProfilesCreateCmd() *cobra.Command {
	var cfgPath, email, deviceAlias, nodeID, pathID, entryIPsCSV, proto string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a profile for a user's device and re-provision it",
		Long: "Create a named profile for a (user, device): choose an egress — a\n" +
			"single node (--node, a direct exit) or a multi-hop path (--path, a\n" +
			"cascade) — optionally a subset of the entry node's IP pool (--entry-ips),\n" +
			"and the data-plane protocol (--protocol amneziawg|xray-reality). The\n" +
			"device is re-provisioned so its sealed bundle carries the new profile.\n\n" +
			"The new peer is pushed to the affected node(s) automatically; if a node\n" +
			"is unreachable the reconcile sweep delivers it when the node returns. The\n" +
			"device picks the profile up on its next sync.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			device, err := resolveDevice(ctx, conn, user.ID, deviceAlias)
			if err != nil {
				return err
			}

			// Validate the egress exists before storing (Validate already enforces
			// exactly one of node/path).
			if nodeID != "" {
				if _, err := fleet.GetNode(ctx, conn, nodeID); err != nil {
					return fmt.Errorf("no such node %q: %w", nodeID, err)
				}
			}
			if pathID != "" {
				if _, err := fleet.GetPath(ctx, conn, pathID); err != nil {
					return fmt.Errorf("no such path %q: %w", pathID, err)
				}
			}

			spec, err := fleet.CreateProfileSpec(ctx, conn, fleet.ProfileSpec{
				UserID:   user.ID,
				DeviceID: device.ID,
				Name:     args[0],
				NodeID:   nodeID,
				PathID:   pathID,
				EntryIPs: splitCSV(entryIPsCSV),
				Protocol: proto,
			})
			if err != nil {
				auditCLI(ctx, conn, "profile.create", "profile", "", map[string]any{"name": args[0], "device_id": device.ID}, err)
				return err
			}
			auditCLI(ctx, conn, "profile.create", "profile", spec.ID, map[string]any{"name": spec.Name, "device_id": spec.DeviceID}, nil)

			fmt.Fprintf(cmd.OutOrStdout(), "profile %s created: %q for %s / %s (%s, %s)\n",
				spec.ID, spec.Name, user.Email, device.Name, egressLabel(spec), spec.Protocol)

			// Re-provision so the device's sealed bundle carries the new profile.
			// A user with no encryption key yet can't be sealed to — the profile is
			// saved and applies on the next (re)provision once they've enrolled.
			res, err := provision.ProvisionDevice(ctx, conn, device.ID, provisionOptions(cfg))
			if errors.Is(err, profile.ErrNoEncryptionKey) {
				fmt.Fprintln(cmd.OutOrStdout(),
					"  note: the user has no encryption key yet — profile saved; it will seal once the device syncs")
				return nil
			}
			if err != nil {
				return fmt.Errorf("re-provision device: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"  re-provisioned: %d profile(s), %d peer(s), revision %d\n", res.ProfileCount, res.PeerCount, res.ProfileVersion)
			pushAffectedNodes(cmd, ctx, cfg, conn, res.AffectedNodes)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&email, "user", "", "the profile owner's email")
	cmd.Flags().StringVar(&deviceAlias, "device", "", "the device alias (optional if the user has one device)")
	cmd.Flags().StringVar(&nodeID, "node", "", "egress: a single node id (direct exit)")
	cmd.Flags().StringVar(&pathID, "path", "", "egress: a multi-hop path id (cascade)")
	cmd.Flags().StringVar(&entryIPsCSV, "entry-ips", "", "subset of the entry node's IPs the client may enter on (comma-separated; default all)")
	cmd.Flags().StringVar(&proto, "protocol", fleet.ProtoAmneziaWG, "data-plane protocol: amneziawg | xray-reality | both")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func newProfilesListCmd() *cobra.Command {
	var cfgPath, email string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List profiles (all, or --user <email>)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			var specs []fleet.ProfileSpec
			if email != "" {
				user, err := account.GetUserByEmail(ctx, conn, email)
				if err != nil {
					return fmt.Errorf("no such user %q: %w", email, err)
				}
				specs, err = fleet.ListProfileSpecsByUser(ctx, conn, user.ID)
				if err != nil {
					return err
				}
			} else if specs, err = fleet.ListProfileSpecs(ctx, conn); err != nil {
				return err
			}
			if len(specs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no profiles")
				return nil
			}

			users := userEmailIndex(ctx, conn)
			devices := deviceNameIndex(ctx, conn)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tUSER\tDEVICE\tEGRESS\tPROTOCOL")
			for _, s := range specs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					s.ID, s.Name, lookup(users, s.UserID), lookup(devices, s.DeviceID), egressLabel(s), s.Protocol)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	cmd.Flags().StringVar(&email, "user", "", "only this user's profiles")
	return cmd
}

func newProfilesRemoveCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:     "rm <profile-id>",
		Aliases: []string{"remove", "delete"},
		Short:   "Delete a profile and re-provision its device",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			spec, err := fleet.GetProfileSpec(ctx, conn, args[0])
			if err != nil {
				return fmt.Errorf("no such profile %q: %w", args[0], err)
			}
			if err := fleet.DeleteProfileSpec(ctx, conn, spec.ID); err != nil {
				auditCLI(ctx, conn, "profile.rm", "profile", spec.ID, map[string]any{"name": spec.Name}, err)
				return err
			}
			auditCLI(ctx, conn, "profile.rm", "profile", spec.ID, map[string]any{"name": spec.Name, "device_id": spec.DeviceID}, nil)
			fmt.Fprintf(cmd.OutOrStdout(), "profile %s (%q) deleted\n", spec.ID, spec.Name)

			// Re-provision so the device's bundle drops the profile and its peer.
			res, err := provision.ProvisionDevice(ctx, conn, spec.DeviceID, provisionOptions(cfg))
			if errors.Is(err, profile.ErrNoEncryptionKey) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("re-provision device: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"  re-provisioned: %d profile(s), %d peer(s), revision %d\n", res.ProfileCount, res.PeerCount, res.ProfileVersion)
			pushAffectedNodes(cmd, ctx, cfg, conn, res.AffectedNodes)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to cox.yaml")
	return cmd
}

// pushAffectedNodes best-effort delivers the current peer set to each node a
// provision changed (Phase 2 push-on-provision). A push failure is non-fatal —
// the reconcile sweep heals it — but is surfaced as a warning so the operator
// knows delivery is pending. Empty when no node was affected (e.g. the user has
// no encryption key yet, so nothing was provisioned).
func pushAffectedNodes(cmd *cobra.Command, ctx context.Context, cfg config.Config, conn *sql.DB, nodeIDs []string) {
	out := cmd.OutOrStdout()
	for _, id := range nodeIDs {
		node, err := fleet.GetNode(ctx, conn, id)
		if err != nil {
			fmt.Fprintf(out, "  warning: push to %s skipped: %v\n", id, err)
			continue
		}
		if node.ControlAddr == "" {
			continue // not yet enrolled — the sweep delivers once it is
		}
		if _, err := reconcile.PushNode(ctx, &cfg, conn, node); err != nil {
			fmt.Fprintf(out, "  warning: push to %s failed (the sweep will retry): %v\n", node.Name, err)
			continue
		}
		fmt.Fprintf(out, "  pushed: %s reconciled\n", node.Name)
	}
}

// resolveDevice finds a user's device by alias, or — when the alias is empty and
// the user owns exactly one device — that device.
func resolveDevice(ctx context.Context, conn *sql.DB, userID, alias string) (account.Device, error) {
	devices, err := account.ListDevicesByUser(ctx, conn, userID)
	if err != nil {
		return account.Device{}, err
	}
	if len(devices) == 0 {
		return account.Device{}, fmt.Errorf("user has no devices — enrol one with `cox devices issue` first")
	}
	if alias == "" {
		if len(devices) == 1 {
			return devices[0], nil
		}
		names := make([]string, len(devices))
		for i, d := range devices {
			names[i] = d.Name
		}
		return account.Device{}, fmt.Errorf("user has several devices — pass --device (one of: %s)", strings.Join(names, ", "))
	}
	for _, d := range devices {
		if d.Name == alias {
			return d, nil
		}
	}
	return account.Device{}, fmt.Errorf("no device %q for this user", alias)
}

// egressLabel renders a profile's egress for display: "node <id>" or "path <id>".
func egressLabel(s fleet.ProfileSpec) string {
	if s.NodeID != "" {
		return "node " + s.NodeID
	}
	return "path " + s.PathID
}

// provisionOptions builds the provisioning settings from the fleet config.
func provisionOptions(cfg config.Config) provision.Options {
	geo := geoip.Open(cfg.GeoIPDatabase,
		filepath.Join(cfg.StateDir, "GeoLite2-City.mmdb"), "GeoLite2-City.mmdb")
	defer geo.Close()
	return provision.Options{
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
		Control: controlEndpoint(geo, hostOnly(cfg.Relay.PublicEndpoint), "", cfg.ControlLocation),
	}
}

// controlEndpoint geo-locates the control-plane endpoint the client syncs
// through (the relay clients reach, else the controller's own IP) for the
// bundle's map pin: geoip first, then the manual control_location config. Zero
// when neither resolves — the client then simply doesn't draw the controller.
func controlEndpoint(geo *geoip.Resolver, relayHost, controllerHost string, manual config.ControlLocationConfig) profile.ControlEndpoint {
	mk := func(city string, lat, lon float64) profile.ControlEndpoint {
		label := "Controller"
		if city != "" {
			label = "Controller · " + city
		}
		return profile.ControlEndpoint{Label: label, City: city, Lat: lat, Lon: lon}
	}
	host := relayHost
	if host == "" {
		host = controllerHost
	}
	if geo != nil && host != "" {
		if loc, ok := geo.Lookup(host); ok && (loc.Latitude != 0 || loc.Longitude != 0) {
			return mk(loc.City, loc.Latitude, loc.Longitude)
		}
	}
	if manual.Lat != 0 || manual.Lon != 0 {
		return mk(manual.City, manual.Lat, manual.Lon)
	}
	return profile.ControlEndpoint{}
}

// userEmailIndex / deviceNameIndex map ids to display labels for listings.
func userEmailIndex(ctx context.Context, conn *sql.DB) map[string]string {
	out := map[string]string{}
	for _, role := range []string{account.RoleAdmin, account.RoleUser} {
		users, err := account.ListUsersByRole(ctx, conn, role)
		if err != nil {
			continue
		}
		for _, u := range users {
			out[u.ID] = u.Email
		}
	}
	return out
}

func deviceNameIndex(ctx context.Context, conn *sql.DB) map[string]string {
	out := map[string]string{}
	specs, err := fleet.ListProfileSpecs(ctx, conn)
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	for _, s := range specs {
		if seen[s.DeviceID] {
			continue
		}
		seen[s.DeviceID] = true
		if d, err := account.GetDevice(ctx, conn, s.DeviceID); err == nil {
			out[s.DeviceID] = d.Name
		}
	}
	return out
}

func lookup(m map[string]string, id string) string {
	if v, ok := m[id]; ok {
		return v
	}
	return id
}
