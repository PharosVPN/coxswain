// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/spf13/cobra"
)

// dbipLiteName is the file the resolver looks for in the state dir (mirrors the
// path serve.go adds to geoip.Open).
const dbipLiteName = "dbip-city-lite.mmdb"

// dbipURL builds the monthly DB-IP City Lite MMDB download URL for a year/month.
func dbipURL(year int, month time.Month) string {
	return fmt.Sprintf("https://download.db-ip.com/free/dbip-city-lite-%04d-%02d.mmdb.gz", year, month)
}

func newGeoIPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "geoip",
		Short: "Manage the IP-geolocation database used to place fleet hosts on the map",
		Long: "Manage the optional IP-geolocation database.\n\n" +
			"Locations are best-effort: without a database the UI falls back to its\n" +
			"region-code map (and you can set a region per node by hand). For city-level\n" +
			"accuracy, either point node.geoip_db at your own MaxMind GeoLite2-City.mmdb,\n" +
			"or run `cox geoip update` to fetch the free, redistributable DB-IP City Lite.",
	}
	cmd.AddCommand(newGeoIPUpdateCmd())
	return cmd
}

func newGeoIPUpdateCmd() *cobra.Command {
	var cfgPath, url, out string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download the free DB-IP City Lite database (CC-BY-4.0) into the state dir",
		Long: "Download the current DB-IP IP-to-City Lite database (MMDB) into the state\n" +
			"directory as " + dbipLiteName + ", where coxswain picks it up automatically.\n\n" +
			"DB-IP City Lite is licensed CC-BY-4.0 — free to use and redistribute WITH\n" +
			"attribution. coxswain credits \"IP Geolocation by DB-IP\" (https://db-ip.com)\n" +
			"on the map whenever this database is in use. MaxMind GeoLite2, if configured\n" +
			"via node.geoip_db, takes precedence over this file.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			dest := out
			if dest == "" {
				dest = filepath.Join(cfg.StateDir, dbipLiteName)
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}

			urls := []string{url}
			if url == "" {
				// The current month's file may not be published yet early in the
				// month, so fall back to the previous month.
				now := time.Now().UTC()
				prev := now.AddDate(0, -1, 0)
				urls = []string{dbipURL(now.Year(), now.Month()), dbipURL(prev.Year(), prev.Month())}
			}

			var lastErr error
			for _, u := range urls {
				fmt.Printf("fetching %s …\n", u)
				if err := fetchDBIP(cmd.Context(), u, dest); err != nil {
					lastErr = err
					fmt.Printf("  %v\n", err)
					continue
				}
				lastErr = nil
				break
			}
			if lastErr != nil {
				return fmt.Errorf("geoip update: %w", lastErr)
			}

			// Validate the file opens and report what we got.
			r := geoip.Open(dest)
			defer r.Close()
			if !r.Available() {
				return fmt.Errorf("geoip update: downloaded file is not a usable MMDB database")
			}
			fmt.Printf("geoip database installed: %s (%s)\n", dest, r.Source())
			if a := r.Attribution(); a.Text != "" {
				fmt.Printf("attribution (required by license): %s — %s\n", a.Text, a.URL)
			}
			fmt.Println("restart `cox serve` to load it.")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	cmd.Flags().StringVar(&url, "url", "", "override the download URL (default: current DB-IP City Lite release)")
	cmd.Flags().StringVar(&out, "out", "", "destination path (default: <state_dir>/"+dbipLiteName+")")
	return cmd
}

// fetchDBIP downloads a gzipped MMDB from url, decompresses it, and writes it to
// dest atomically (temp file + rename), so a failed/partial download never
// replaces a working database.
func fetchDBIP(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dbip-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dest)
}
