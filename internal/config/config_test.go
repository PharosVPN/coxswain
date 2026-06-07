// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestPresetWriteLoadRoundTrip(t *testing.T) {
	for _, posture := range []Posture{PosturePersonal, PostureEnterprise} {
		t.Run(string(posture), func(t *testing.T) {
			want, err := Preset(posture)
			if err != nil {
				t.Fatalf("Preset: %v", err)
			}
			path := filepath.Join(t.TempDir(), "cox.yaml")
			if err := Write(path, want, false); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.Posture != want.Posture {
				t.Errorf("posture: got %q want %q", got.Posture, want.Posture)
			}
			if got.Retention != want.Retention {
				t.Errorf("retention: got %+v want %+v", got.Retention, want.Retention)
			}
			if got.Protocols != want.Protocols {
				t.Errorf("protocols: got %+v want %+v", got.Protocols, want.Protocols)
			}
			if !reflect.DeepEqual(got.Relay, want.Relay) {
				t.Errorf("relay: got %+v want %+v", got.Relay, want.Relay)
			}
		})
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cox.yaml")
	cfg, _ := Preset(PosturePersonal)
	if err := Write(path, cfg, false); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := Write(path, cfg, false); err == nil {
		t.Fatal("second Write: expected error, got nil")
	}
	if err := Write(path, cfg, true); err != nil {
		t.Fatalf("Write with force: %v", err)
	}
}

func TestEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cox.yaml")
	cfg, _ := Preset(PosturePersonal)
	if err := Write(path, cfg, false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	t.Setenv("COX_UI__LISTEN", "127.0.0.1:9999")
	t.Setenv("COX_LOG__LEVEL", "debug")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.UI.Listen != "127.0.0.1:9999" {
		t.Errorf("ui.listen: got %q want overridden value", got.UI.Listen)
	}
	if got.Log.Level != "debug" {
		t.Errorf("log.level: got %q want debug", got.Log.Level)
	}
}

func TestReconcileSecondsDefaults(t *testing.T) {
	// Unset / non-positive falls back to the default; a positive value is honoured.
	if got := (FleetConfig{}).ReconcileSeconds(); got != DefaultReconcileSeconds {
		t.Errorf("unset ReconcileSeconds() = %d, want default %d", got, DefaultReconcileSeconds)
	}
	if got := (FleetConfig{ReconcileInterval: -5}).ReconcileSeconds(); got != DefaultReconcileSeconds {
		t.Errorf("negative ReconcileSeconds() = %d, want default %d", got, DefaultReconcileSeconds)
	}
	if got := (FleetConfig{ReconcileInterval: 30}).ReconcileSeconds(); got != 30 {
		t.Errorf("ReconcileSeconds() = %d, want 30", got)
	}
	// The presets carry the field through a write/load round-trip.
	for _, posture := range []Posture{PosturePersonal, PostureEnterprise} {
		c, _ := Preset(posture)
		if c.Fleet.ReconcileInterval != DefaultReconcileSeconds {
			t.Errorf("%s preset reconcile_interval = %d, want %d", posture, c.Fleet.ReconcileInterval, DefaultReconcileSeconds)
		}
	}
}

func TestValidateRejectsBadPosture(t *testing.T) {
	c := Config{Posture: "bogus", StateDir: "./state"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation error for bogus posture")
	}
}

func TestPresetUnknownPosture(t *testing.T) {
	if _, err := Preset("bogus"); err == nil {
		t.Fatal("expected error for unknown posture")
	}
}
