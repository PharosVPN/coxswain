// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/ssh"
	"github.com/spf13/cobra"
)

func newSSHKeyCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "ssh-key",
		Short: "Print coxswain's SSH public key",
		Long: "Print coxswain's outbound SSH public key. Add this key to a new\n" +
			"node's ~/.ssh/authorized_keys (or the cloud provider's SSH keys)\n" +
			"before running `cox nodes add` — coxswain dials out with it to\n" +
			"install the buoy agent.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			id, _, err := ssh.EnsureIdentity(cmd.Context(), conn)
			if err != nil {
				return err
			}
			fmt.Println(id.AuthorizedKey)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}
