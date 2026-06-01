// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var (
		personal   bool
		enterprise bool
		cfgPath    string
		stateDir   string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialise a new coxswain controller",
		Long: "Initialise a new coxswain controller from a deployment preset.\n\n" +
			"Writes a config file, creates the state directory, applies the\n" +
			"SQLite schema, and generates the in-repo certificate authority.\n" +
			"Safe to inspect before first run; re-running is refused unless\n" +
			"--force is given.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			posture := config.PosturePersonal
			if enterprise {
				posture = config.PostureEnterprise
			}
			return runInit(cmd.Context(), initOptions{
				posture:  posture,
				cfgPath:  cfgPath,
				stateDir: stateDir,
				force:    force,
			})
		},
	}

	cmd.Flags().BoolVar(&personal, "personal", false, "personal preset: one operator, a few nodes")
	cmd.Flags().BoolVar(&enterprise, "enterprise", false, "enterprise preset: many users, many regions")
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path of the config file to write")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "override the preset state directory")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config file")
	cmd.MarkFlagsOneRequired("personal", "enterprise")
	cmd.MarkFlagsMutuallyExclusive("personal", "enterprise")

	return cmd
}

type initOptions struct {
	posture  config.Posture
	cfgPath  string
	stateDir string
	force    bool
}

func runInit(ctx context.Context, opt initOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Fail before touching disk if the config is already there.
	if !opt.force {
		if _, err := os.Stat(opt.cfgPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", opt.cfgPath)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	cfg, err := config.Preset(opt.posture)
	if err != nil {
		return err
	}
	if opt.stateDir != "" {
		cfg.StateDir = opt.stateDir
	}

	adminPassword, err := generatePassword()
	if err != nil {
		return err
	}
	cfg.Admin.Password = adminPassword

	snapshotsDir := filepath.Join(cfg.StateDir, "snapshots")
	if err := os.MkdirAll(snapshotsDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	dbPath := filepath.Join(cfg.StateDir, "app.db")
	conn, err := db.Open(dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := db.Migrate(conn); err != nil {
		return err
	}

	bundle, created, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		return fmt.Errorf("certificate authority: %w", err)
	}

	if err := config.Write(opt.cfgPath, cfg, opt.force); err != nil {
		return err
	}

	fmt.Printf("coxswain initialised — %s posture\n", cfg.Posture)
	fmt.Printf("  config       %s\n", opt.cfgPath)
	fmt.Printf("  state        %s\n", cfg.StateDir)
	fmt.Printf("  database     %s\n", dbPath)
	if created {
		fmt.Printf("  CA           generated (root + fleet + device)\n")
	} else {
		fmt.Printf("  CA           reused existing\n")
	}
	fmt.Printf("  root CA SHA-256\n               %s\n", bundle.Root.Fingerprint())
	fmt.Printf("  admin login  user \"admin\", password: %s\n", adminPassword)
	fmt.Printf("               (stored in %s — edit there and restart to change)\n", opt.cfgPath)
	return nil
}

// generatePassword returns a 120-bit random password as lowercase base32.
func generatePassword() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate admin password: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
