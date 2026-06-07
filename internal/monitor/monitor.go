// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package monitor turns the ephemeral node WatchEvents firehose into a
// persisted, source-IP-aware session history. coxswain's live plane (package
// live) hands every node event to a Store: the Store resolves the data-plane
// peer public key to a device/user, derives the client source IP from the
// source endpoint, and writes a connection_events row for session boundaries
// (connect/disconnect, and source-IP changes). This is the foundation the
// analytics engine (Phase C) consumes; the /api/sessions route and the live
// /ws/events stream both read its output.
//
// Persistence is best-effort and non-blocking: ingestion enqueues onto a
// buffered channel drained by a background worker, so a slow or stuck database
// write never stalls the live event stream. A full queue drops the overflow
// (counted) rather than back-pressuring the fleet.
package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PharosVPN/coxswain/internal/idgen"
)

// Event is one resolved, source-IP-aware session event ready to persist. The
// live plane builds it from a node proto event plus the Store's peer resolution.
type Event struct {
	At             time.Time
	NodeID         string
	PeerID         string // data-plane peer public key
	DeviceID       string // resolved; "" when the peer is unknown
	UserID         string // resolved; "" when the peer is unknown
	Protocol       string
	EventType      string // "connect" | "disconnect" | "handshake"
	SourceIP       string // source endpoint with the port stripped
	SourceEndpoint string // full client IP:port
	RxBytes        uint64
	TxBytes        uint64
	// Reason annotates why a disconnect was written. Empty for an ordinary
	// node-reported event; "stream-lost" for a synthetic disconnect the
	// controller writes when a node's stream drops (LOW-14), so a dangling
	// session is closed out rather than left open forever.
	Reason string
}

// Resolution is the device/user a peer public key maps to.
type Resolution struct {
	DeviceID string
	UserID   string
}

// ingestBuffer is how many events may queue for the writer before further
// events are dropped. A handful of nodes emit on transitions only, so this is
// generous; a stuck DB writer sheds the overflow rather than blocking the
// stream.
const ingestBuffer = 1024

// dropReportInterval is how often the Run loop checks whether the dropped
// counter has advanced and, if so, logs it. Silent ingest loss is invisible
// otherwise; this surfaces it at a bounded, rate-limited cadence.
const dropReportInterval = 60 * time.Second

// Store is the connection-history ingestion sink. It owns a background writer
// goroutine and an in-memory peer→device/user cache so the hot path never
// blocks on the database for a resolution it has already seen.
type Store struct {
	db  *sql.DB
	log *slog.Logger

	queue   chan Event
	dropped atomic.Uint64

	mu    sync.RWMutex
	cache map[string]Resolution // peer public key → resolution

	startOnce sync.Once
}

// NewStore returns a Store backed by db. Call Run with the serve context to
// start the background writer before ingesting.
func NewStore(db *sql.DB, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{
		db:    db,
		log:   log,
		queue: make(chan Event, ingestBuffer),
		cache: make(map[string]Resolution),
	}
}

// Run drains the ingest queue, writing rows until ctx is cancelled. It is safe
// to call once; a second call is a no-op. Persistence happens here, off the
// stream goroutine, so a database stall never stalls the live plane.
func (s *Store) Run(ctx context.Context) {
	if s == nil {
		return
	}
	s.startOnce.Do(func() {
		// Periodically surface silent ingest loss: a full queue sheds events
		// (counted in s.dropped) without blocking the stream, so without this
		// the loss is invisible. Log only the delta, rate-limited to the ticker.
		dropTicker := time.NewTicker(dropReportInterval)
		defer dropTicker.Stop()
		var lastDropped uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-dropTicker.C:
				if d := s.dropped.Load(); d > lastDropped {
					s.log.Warn("monitor: dropped connection events (ingest queue full)",
						"dropped_total", d, "dropped_since_last", d-lastDropped)
					lastDropped = d
				}
			case ev := <-s.queue:
				s.write(ctx, ev)
			}
		}
	})
}

// Resolve maps a data-plane peer public key to its device and user. It serves
// from an in-memory cache and falls back to a single indexed query joining
// peers → devices. An unknown peer resolves to a zero Resolution (and is
// cached, so a noisy unknown peer does not hammer the database).
func (s *Store) Resolve(ctx context.Context, peerID string) Resolution {
	if s == nil || peerID == "" {
		return Resolution{}
	}
	s.mu.RLock()
	r, ok := s.cache[peerID]
	s.mu.RUnlock()
	if ok {
		return r
	}

	var deviceID, userID sql.NullString
	// peers.public_key holds the AmneziaWG public key / XRay UUID; devices ties
	// it to the owning user. LIMIT 1 — a peer maps to exactly one device.
	err := s.db.QueryRowContext(ctx, `
		SELECT p.device_id, d.user_id
		FROM peers p
		JOIN devices d ON d.id = p.device_id
		WHERE p.public_key = ?
		LIMIT 1`, peerID).Scan(&deviceID, &userID)
	if err != nil && err != sql.ErrNoRows {
		// A resolution failure must never break ingestion; log and treat as
		// unknown, but do not cache (so a transient error can recover).
		s.log.Warn("monitor: resolve peer failed", "err", err)
		return Resolution{}
	}
	res := Resolution{DeviceID: deviceID.String, UserID: userID.String}
	s.mu.Lock()
	s.cache[peerID] = res
	s.mu.Unlock()
	return res
}

// Forget drops a peer's cached resolution. The live plane calls it when a peer
// disconnects for good, so a re-provisioned key resolves afresh.
func (s *Store) Forget(peerID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.cache, peerID)
	s.mu.Unlock()
}

// Ingest enqueues a resolved event for persistence. It never blocks: a full
// queue drops the event (counted via Dropped) rather than stalling the caller's
// live stream. Only session boundaries should be ingested — see live.streamNode.
func (s *Store) Ingest(ev Event) {
	if s == nil {
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
}

// Dropped reports how many events were shed because the writer fell behind.
func (s *Store) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// write persists one event. Failures are logged, never propagated — a database
// hiccup must not affect the live stream that fed this row.
func (s *Store) write(ctx context.Context, ev Event) {
	at := ev.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO connection_events
		(id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		idgen.New("cev"), at.UTC(), ev.NodeID, ev.PeerID,
		nullable(ev.DeviceID), nullable(ev.UserID), ev.Protocol, ev.EventType,
		ev.SourceIP, ev.SourceEndpoint, ev.RxBytes, ev.TxBytes, ev.Reason)
	if err != nil {
		s.log.Warn("monitor: persist connection event failed", "err", err)
	}
}

// SourceIP derives the client IP from an IP:port source endpoint, stripping the
// port. An endpoint without a port (or empty) is returned unchanged; an empty
// endpoint yields "".
func SourceIP(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	// Not host:port — maybe a bare IP. Strip brackets from a bare IPv6 literal.
	return strings.Trim(endpoint, "[]")
}

// nullable converts an empty string to a SQL NULL so unresolved device/user
// columns are NULL, not "".
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Purge deletes connection_events older than `days` days. days <= 0 is a no-op
// (history retention disabled). It returns the number of rows removed.
func Purge(ctx context.Context, db *sql.DB, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	res, err := db.ExecContext(ctx, `DELETE FROM connection_events WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("monitor: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
