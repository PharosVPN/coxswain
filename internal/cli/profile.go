// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/pharos"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/spf13/cobra"
)

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Export user profiles",
	}
	cmd.AddCommand(newProfileExportCmd())
	return cmd
}

func newProfileExportCmd() *cobra.Command {
	var cfgPath, out string
	cmd := &cobra.Command{
		Use:   "export <user-id>",
		Short: "Export a user's latest profile as an account-mode .pharos file",
		Long: "Export a user's latest sealed profile as a `.pharos` file in\n" +
			"account mode (DESIGN §9). coxswain stores only ciphertext, so the file\n" +
			"is the sealed bundle — only the user's device can decrypt it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID := args[0]
			_, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			ciphertext, revision, err := profile.LatestCiphertext(cmd.Context(), conn, userID)
			if errors.Is(err, profile.ErrNoProfile) {
				return fmt.Errorf("no profile has been issued for %s", userID)
			}
			if err != nil {
				return err
			}

			var bundle e2e.SealedBundle
			if err := json.Unmarshal(ciphertext, &bundle); err != nil {
				return fmt.Errorf("stored profile is malformed: %w", err)
			}
			file, err := pharos.WrapSealedBundle(bundle)
			if err != nil {
				return err
			}

			path := out
			if path == "" {
				path = userID + pharos.Extension
			}
			if err := os.WriteFile(path, file, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}

			fmt.Printf("exported profile revision %d\n", revision)
			fmt.Printf("  user  %s\n", userID)
			fmt.Printf("  file  %s (account mode — opens only on the user's device)\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&out, "out", "", "output path (default <user-id>.pharos)")
	return cmd
}
