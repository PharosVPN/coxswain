// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package analytics

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// seedDisconnectBytes inserts one disconnect connection_events row carrying a
// session tx_bytes (and rx_bytes) delta, so the data_volume rule has a real
// outbound figure to reason over. The shared seedEvent always writes 0 bytes;
// this helper is the byte-bearing equivalent.
func seedDisconnectBytes(t *testing.T, conn *sql.DB, deviceID, nodeID, sourceIP string, rx, tx uint64, at time.Time) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(), `
		INSERT INTO connection_events
		(id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'disconnect', ?, ?, ?, ?)`,
		idgen.New("cev"), at.UTC(), nodeID, "pk", deviceID, "usr_1", "amneziawg",
		sourceIP, sourceIP+":1194", rx, tx)
	if err != nil {
		t.Fatalf("seed disconnect bytes: %v", err)
	}
}

// seedBaselineSessions seeds `count` prior completed (disconnect) sessions all
// carrying the same tx_bytes, spread one per day before the window, building a
// device's median baseline = perTx.
func seedBaselineSessions(t *testing.T, conn *sql.DB, dev string, count int, perTx uint64) {
	t.Helper()
	for i := 1; i <= count; i++ {
		// Spread one per day starting two days back, so every baseline session is
		// strictly before the 24h sweep window (none lands inside it as the window
		// start) and all `count` are counted in the median.
		at := fixedNow.Add(-time.Duration(i+1) * 24 * time.Hour)
		seedDisconnectBytes(t, conn, dev, "node_base", "203.0.113.9", perTx, perTx, at)
	}
}

const (
	gib = uint64(1) << 30
	mib = uint64(1) << 20
)

// TestDataVolumeExfilFires: a device with a solid low-volume baseline closes one
// session whose tx far exceeds both the floor and 10× its median → warning.
func TestDataVolumeExfilFires(t *testing.T) {
	conn := testDB(t)
	dev := "dev_exfil"
	// Baseline: 24 prior sessions of ~50 MiB each → median 50 MiB.
	seedBaselineSessions(t, conn, dev, 24, 50*mib)
	// A window session shipping 4 GiB out: clears the 1 GiB floor and is ~80× the
	// 50 MiB median (well past 10×).
	seedDisconnectBytes(t, conn, dev, "node_x", "198.51.100.20", 100*mib, 4*gib, fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)

	got := alertsOfKind(t, conn, KindDataVolumeExfil)
	if len(got) != 1 {
		t.Fatalf("data_volume_exfil: got %d want 1", len(got))
	}
	a := got[0]
	if a.Severity != SeverityWarning {
		t.Errorf("severity = %q want warning", a.Severity)
	}
	if a.DeviceID != dev {
		t.Errorf("device = %q want %q", a.DeviceID, dev)
	}
	if tx, _ := a.Detail["tx_bytes"].(float64); uint64(tx) != 4*gib {
		t.Errorf("tx_bytes = %v want %d", a.Detail["tx_bytes"], 4*gib)
	}
	if med, _ := a.Detail["median_tx_bytes"].(float64); uint64(med) != 50*mib {
		t.Errorf("median_tx_bytes = %v want %d", a.Detail["median_tx_bytes"], 50*mib)
	}
	if f, _ := a.Detail["factor_over_median"].(float64); f < float64(dataVolumeFactor) {
		t.Errorf("factor_over_median = %v want >= %d", a.Detail["factor_over_median"], dataVolumeFactor)
	}
	if n, _ := a.Detail["baseline_sessions"].(float64); int(n) != 24 {
		t.Errorf("baseline_sessions = %v want 24", a.Detail["baseline_sessions"])
	}
	if len(a.SourceIPs) != 1 || a.SourceIPs[0] != "198.51.100.20" {
		t.Errorf("source_ips = %v want [198.51.100.20]", a.SourceIPs)
	}
}

// TestDataVolumeExfilBelowFloorDoesNotFire: a session that is a huge multiple of
// a tiny median but under the 1 GiB absolute floor must NOT fire — not enough
// data leaving to matter.
func TestDataVolumeExfilBelowFloorDoesNotFire(t *testing.T) {
	conn := testDB(t)
	dev := "dev_under_floor"
	// Median 2 MiB; a 200 MiB session is 100× the median but well under 1 GiB.
	seedBaselineSessions(t, conn, dev, 24, 2*mib)
	seedDisconnectBytes(t, conn, dev, "node_x", "198.51.100.20", 10*mib, 200*mib, fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindDataVolumeExfil); len(got) != 0 {
		t.Fatalf("below-floor session produced %d data_volume alerts want 0", len(got))
	}
}

// TestDataVolumeExfilBelowFactorDoesNotFire: a heavy user whose median is already
// large — the session clears the floor but is under 10× the median, so it is a
// normal big upload for THIS device and must NOT fire.
func TestDataVolumeExfilBelowFactorDoesNotFire(t *testing.T) {
	conn := testDB(t)
	dev := "dev_heavy"
	// Median 800 MiB (a heavy user). A 4 GiB session clears the floor but is only
	// 5× the median — under the 10× factor.
	seedBaselineSessions(t, conn, dev, 24, 800*mib)
	seedDisconnectBytes(t, conn, dev, "node_x", "198.51.100.20", 1*gib, 4*gib, fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindDataVolumeExfil); len(got) != 0 {
		t.Fatalf("below-factor session produced %d data_volume alerts want 0", len(got))
	}
}

// TestDataVolumeExfilThinHistoryDoesNotFire: a device with fewer than
// dataVolumeMinSessions prior sessions has no trusted baseline, so even a clear
// over-floor, over-factor session must NOT fire.
func TestDataVolumeExfilThinHistoryDoesNotFire(t *testing.T) {
	conn := testDB(t)
	dev := "dev_thin_hist"
	// Only 5 prior sessions (median 20 MiB) — below the 20-session minimum.
	seedBaselineSessions(t, conn, dev, 5, 20*mib)
	seedDisconnectBytes(t, conn, dev, "node_x", "198.51.100.20", 100*mib, 8*gib, fixedNow.Add(-1*time.Hour))

	sweep(t, conn, nil)
	if got := alertsOfKind(t, conn, KindDataVolumeExfil); len(got) != 0 {
		t.Fatalf("thin-history device produced %d data_volume alerts want 0", len(got))
	}
}

// TestDataVolumeExfilDedupRefreshesNotDuplicates: two sweeps over the same
// over-baseline session (same UTC day) yield ONE open alert — dedup collapses
// the repeat rather than spamming.
func TestDataVolumeExfilDedupRefreshesNotDuplicates(t *testing.T) {
	conn := testDB(t)
	dev := "dev_exfil_dedup"
	seedBaselineSessions(t, conn, dev, 24, 50*mib)
	seedDisconnectBytes(t, conn, dev, "node_x", "198.51.100.20", 100*mib, 4*gib, fixedNow.Add(-1*time.Hour))

	// First sweep opens the alert.
	fresh1 := sweep(t, conn, nil)
	if !containsKind(fresh1, KindDataVolumeExfil) {
		t.Fatalf("first sweep did not open a data_volume alert")
	}
	// A second over-baseline session the same day keeps the condition live; a
	// second sweep must REFRESH, not insert a duplicate.
	seedDisconnectBytes(t, conn, dev, "node_y", "192.0.2.30", 100*mib, 5*gib, fixedNow.Add(-30*time.Minute))
	fresh2, err := Sweep(context.Background(), conn, nil, fixedNow.Add(time.Minute), DefaultWindow)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}

	got := alertsOfKind(t, conn, KindDataVolumeExfil)
	if len(got) != 1 {
		t.Fatalf("dedup: got %d data_volume alerts after two sweeps want 1", len(got))
	}
	if containsKind(fresh2, KindDataVolumeExfil) {
		t.Errorf("second sweep reported the refreshed alert as fresh; should be silent")
	}
}

// TestMedianU64 spot-checks the median helper on odd, even, empty, and
// single-element slices.
func TestMedianU64(t *testing.T) {
	cases := []struct {
		in   []uint64
		want uint64
	}{
		{nil, 0},
		{[]uint64{5}, 5},
		{[]uint64{3, 1, 2}, 2},    // odd → middle
		{[]uint64{1, 2, 3, 4}, 2}, // even → (2+3)/2 floored via halving = 1+1 = 2
		{[]uint64{10, 10, 10, 10, 10}, 10},
	}
	for _, c := range cases {
		if got := medianU64(c.in); got != c.want {
			t.Errorf("medianU64(%v) = %d want %d", c.in, got, c.want)
		}
	}
}
