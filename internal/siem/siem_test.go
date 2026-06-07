// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package siem

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/authn"
	"github.com/PharosVPN/coxswain/internal/db"
	monitorv1 "github.com/PharosVPN/coxswain/internal/gen/pharos/monitor/v1"
	"github.com/PharosVPN/coxswain/internal/live"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return conn
}

// mintToken creates an API token of the given scope and returns its secret.
func mintToken(t *testing.T, conn *sql.DB, name string, scope authn.Scope) string {
	t.Helper()
	secret, _, err := authn.Create(context.Background(), conn, name, scope, 0, "test")
	if err != nil {
		t.Fatalf("authn.Create(%s): %v", scope, err)
	}
	return secret
}

// expiredToken mints a token that is already expired.
func expiredToken(t *testing.T, conn *sql.DB) string {
	t.Helper()
	secret, rec, err := authn.Create(context.Background(), conn, "stale", authn.ScopeMonitor, time.Hour, "test")
	if err != nil {
		t.Fatalf("authn.Create: %v", err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := conn.Exec(`UPDATE api_tokens SET expires_at = ? WHERE id = ?`, past, rec.ID); err != nil {
		t.Fatalf("force-expire: %v", err)
	}
	return secret
}

// harness wires a bufconn-backed MonitorStream server with the real auth
// interceptor, returning a client and the underlying hub.
type harness struct {
	hub    *live.Hub
	client monitorv1.MonitorStreamClient
	srv    *Server
}

func newHarness(t *testing.T, conn *sql.DB) *harness {
	t.Helper()
	hub := live.NewHub()
	srv := NewServer(hub, nil)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.ChainStreamInterceptor(AuthInterceptor(conn)))
	monitorv1.RegisterMonitorStreamServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn2, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn2.Close() })

	return &harness{hub: hub, client: monitorv1.NewMonitorStreamClient(conn2), srv: srv}
}

// authCtx returns a context carrying a Bearer token in gRPC metadata.
func authCtx(parent context.Context, secret string) context.Context {
	return metadata.AppendToOutgoingContext(parent, "authorization", "Bearer "+secret)
}

// --- Interceptor auth tests -------------------------------------------------

// TestInterceptorAcceptsMonitor: a monitor-scope token opens the stream.
func TestInterceptorAcceptsMonitor(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	secret := mintToken(t, conn, "mon", authn.ScopeMonitor)

	assertAccept(t, h, authCtx(context.Background(), secret))
}

// TestInterceptorAcceptsAdmin: admin outranks monitor, so it is also allowed.
func TestInterceptorAcceptsAdmin(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	secret := mintToken(t, conn, "adm", authn.ScopeAdmin)

	assertAccept(t, h, authCtx(context.Background(), secret))
}

// assertAccept opens a stream with ctx and asserts the server accepted it past
// the interceptor — observed by the handler registering as a hub subscriber. A
// server-streaming RPC sends no headers until its first message, so we cannot
// use stream.Header() (it would block forever on an idle-but-accepted stream);
// the hub subscription is the reliable "accepted" signal.
func assertAccept(t *testing.T, h *harness, ctx context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, err := h.client.Subscribe(ctx, &monitorv1.SubscribeRequest{}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.hub.Subscribers() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("token accepted check: server never subscribed to the hub")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestInterceptorRejectsReadonly: readonly is below monitor → PermissionDenied.
func TestInterceptorRejectsReadonly(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	secret := mintToken(t, conn, "ro", authn.ScopeReadonly)

	assertReject(t, h, authCtx(context.Background(), secret), codes.PermissionDenied)
}

// TestInterceptorRejectsNoToken: missing metadata → Unauthenticated.
func TestInterceptorRejectsNoToken(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)

	assertReject(t, h, context.Background(), codes.Unauthenticated)
}

// TestInterceptorRejectsGarbage: an unknown secret → Unauthenticated.
func TestInterceptorRejectsGarbage(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)

	assertReject(t, h, authCtx(context.Background(), "cox_mon_notarealtoken"), codes.Unauthenticated)
}

// TestInterceptorRejectsExpired: an expired token → Unauthenticated.
func TestInterceptorRejectsExpired(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	secret := expiredToken(t, conn)

	assertReject(t, h, authCtx(context.Background(), secret), codes.Unauthenticated)
}

// assertReject opens a stream with ctx and asserts the first Recv fails with the
// expected gRPC code.
func assertReject(t *testing.T, h *harness, ctx context.Context, want codes.Code) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := h.client.Subscribe(ctx, &monitorv1.SubscribeRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != want {
		t.Fatalf("got code %v (err %v), want %v", status.Code(err), err, want)
	}
}

// --- Subscribe streaming tests ----------------------------------------------

// recvWithin reads one event, failing the test if none arrives in time.
func recvWithin(t *testing.T, stream monitorv1.MonitorStream_SubscribeClient, d time.Duration) *monitorv1.MonitorEvent {
	t.Helper()
	type res struct {
		ev  *monitorv1.MonitorEvent
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ev, err := stream.Recv()
		ch <- res{ev, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Recv: %v", r.err)
		}
		return r.ev
	case <-time.After(d):
		t.Fatalf("timed out waiting for event")
		return nil
	}
}

// subscribeReady opens a monitor-authed stream and blocks until the server has
// registered as a hub subscriber, so a subsequent Publish is not raced.
func subscribeReady(t *testing.T, h *harness, conn *sql.DB, req *monitorv1.SubscribeRequest) (monitorv1.MonitorStream_SubscribeClient, context.CancelFunc) {
	t.Helper()
	secret := mintToken(t, conn, "mon-"+t.Name(), authn.ScopeMonitor)
	ctx, cancel := context.WithCancel(authCtx(context.Background(), secret))
	stream, err := h.client.Subscribe(ctx, req)
	if err != nil {
		cancel()
		t.Fatalf("Subscribe: %v", err)
	}
	// A server-streaming RPC sends no headers until its first message, so we
	// cannot block on stream.Header() to confirm readiness. Instead poll until
	// the handler has registered as a hub subscriber — then a Publish won't race.
	deadline := time.Now().Add(2 * time.Second)
	for h.hub.Subscribers() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("server never subscribed to the hub")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return stream, cancel
}

// TestSubscribeDeliversSessionEvent: a hub-published connect event arrives as a
// translated SessionEvent.
func TestSubscribeDeliversSessionEvent(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	stream, cancel := subscribeReady(t, h, conn, &monitorv1.SubscribeRequest{})
	defer cancel()

	at := time.Now().UTC().Truncate(time.Second)
	h.hub.Publish(live.Event{
		Type:           "PEER_CONNECTED",
		At:             at,
		NodeID:         "node-1",
		DeviceID:       "dev-1",
		User:           "user-1",
		Protocol:       "AMNEZIAWG",
		SourceIP:       "203.0.113.5",
		SourceEndpoint: "203.0.113.5:51820",
	})

	ev := recvWithin(t, stream, 2*time.Second)
	if ev.GetType() != "connect" {
		t.Fatalf("type = %q, want connect", ev.GetType())
	}
	if ev.GetAlert() != nil {
		t.Fatalf("session event carried an alert payload")
	}
	s := ev.GetSession()
	if s == nil {
		t.Fatal("session payload is nil")
	}
	if s.GetEventType() != "connect" || s.GetNodeId() != "node-1" || s.GetDeviceId() != "dev-1" ||
		s.GetUserId() != "user-1" || s.GetProtocol() != "AMNEZIAWG" ||
		s.GetSourceIp() != "203.0.113.5" || s.GetSourceEndpoint() != "203.0.113.5:51820" {
		t.Fatalf("session fields mismatched: %+v", s)
	}
	if !ev.GetAt().AsTime().Equal(at) {
		t.Fatalf("at = %v, want %v", ev.GetAt().AsTime(), at)
	}
}

// TestSubscribeDeliversAlertEvent: a hub-published alert arrives as a translated
// AlertEvent with the detail map JSON-encoded.
func TestSubscribeDeliversAlertEvent(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	stream, cancel := subscribeReady(t, h, conn, &monitorv1.SubscribeRequest{})
	defer cancel()

	at := time.Now().UTC()
	alert := analytics.Alert{
		ID:        "alr-1",
		Kind:      "impossible_travel",
		Severity:  "high",
		DeviceID:  "dev-9",
		UserID:    "user-9",
		SourceIPs: []string{"198.51.100.1", "203.0.113.9"},
		Detail:    map[string]any{"km": 9000.0},
	}
	h.hub.PublishAlert(alert, alert.DeviceID, at)

	ev := recvWithin(t, stream, 2*time.Second)
	if ev.GetType() != "alert" {
		t.Fatalf("type = %q, want alert", ev.GetType())
	}
	if ev.GetSession() != nil {
		t.Fatalf("alert event carried a session payload")
	}
	a := ev.GetAlert()
	if a == nil {
		t.Fatal("alert payload is nil")
	}
	if a.GetId() != "alr-1" || a.GetKind() != "impossible_travel" || a.GetSeverity() != "high" ||
		a.GetDeviceId() != "dev-9" || a.GetUserId() != "user-9" {
		t.Fatalf("alert fields mismatched: %+v", a)
	}
	if len(a.GetSourceIps()) != 2 || a.GetSourceIps()[0] != "198.51.100.1" {
		t.Fatalf("source_ips mismatched: %v", a.GetSourceIps())
	}
	if a.GetDetailJson() != `{"km":9000}` {
		t.Fatalf("detail_json = %q, want %q", a.GetDetailJson(), `{"km":9000}`)
	}
}

// TestSubscribeKindsFilter: with kinds=["alert"], session events are filtered
// out and only the alert is delivered.
func TestSubscribeKindsFilter(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	stream, cancel := subscribeReady(t, h, conn, &monitorv1.SubscribeRequest{Kinds: []string{"alert"}})
	defer cancel()

	// A connect that must be filtered out, then an alert that must pass.
	h.hub.Publish(live.Event{Type: "PEER_CONNECTED", At: time.Now().UTC(), NodeID: "n", PeerID: "p"})
	h.hub.PublishAlert(analytics.Alert{ID: "alr-2", Kind: "new_geo", Severity: "low"}, "", time.Now().UTC())

	ev := recvWithin(t, stream, 2*time.Second)
	if ev.GetType() != "alert" {
		t.Fatalf("first delivered event type = %q, want alert (connect should be filtered)", ev.GetType())
	}
	if ev.GetAlert().GetId() != "alr-2" {
		t.Fatalf("alert id = %q, want alr-2", ev.GetAlert().GetId())
	}
}

// TestSubscribeSkipsNonSessionEvents: handshake/error live events are not
// session or alert signal, so the SIEM stream drops them; the next session event
// is what arrives.
func TestSubscribeSkipsNonSessionEvents(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	stream, cancel := subscribeReady(t, h, conn, &monitorv1.SubscribeRequest{})
	defer cancel()

	h.hub.Publish(live.Event{Type: "HANDSHAKE_UP", At: time.Now().UTC()})
	h.hub.Publish(live.Event{Type: "ERROR", At: time.Now().UTC()})
	h.hub.Publish(live.Event{Type: "PEER_DISCONNECTED", At: time.Now().UTC(), NodeID: "n2", PeerID: "p2"})

	ev := recvWithin(t, stream, 2*time.Second)
	if ev.GetType() != "disconnect" {
		t.Fatalf("type = %q, want disconnect (handshake/error must be skipped)", ev.GetType())
	}
}

// TestTranslateUnknownAlertPayload: an alert event whose payload is not an
// analytics.Alert still yields a minimal AlertEvent rather than panicking.
func TestTranslateUnknownAlertPayload(t *testing.T) {
	ev := live.Event{Type: "alert", DeviceID: "d", Alert: "not-an-alert"}
	me, keep := translate(ev)
	if !keep {
		t.Fatal("alert event was dropped")
	}
	if me.GetAlert() == nil || me.GetAlert().GetDeviceId() != "d" {
		t.Fatalf("unexpected alert: %+v", me.GetAlert())
	}
	if me.GetAlert().GetDetailJson() != "{}" {
		t.Fatalf("detail_json = %q, want {}", me.GetAlert().GetDetailJson())
	}
}

// TestStreamClosesOnClientCancel: cancelling the client context tears the stream
// down and unsubscribes from the hub.
func TestStreamClosesOnClientCancel(t *testing.T) {
	conn := testDB(t)
	h := newHarness(t, conn)
	stream, cancel := subscribeReady(t, h, conn, &monitorv1.SubscribeRequest{})

	cancel()
	// Recv should now return an error (context cancelled / EOF).
	if _, err := stream.Recv(); err == nil {
		t.Fatal("Recv returned nil after cancel, want error")
	}
	// The server should drop its hub subscription shortly after.
	deadline := time.Now().Add(2 * time.Second)
	for h.hub.Subscribers() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never unsubscribed after client cancel")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestOnSubscribeCalled: the onSubscribe hook fires once per accepted consumer
// with the authenticated token in context.
func TestOnSubscribeCalled(t *testing.T) {
	conn := testDB(t)
	hub := live.NewHub()

	called := make(chan string, 1)
	srv := NewServer(hub, func(sctx context.Context) {
		name := ""
		if tok, ok := TokenFromContext(sctx); ok {
			name = tok.Name
		}
		called <- name
	})

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.ChainStreamInterceptor(AuthInterceptor(conn)))
	monitorv1.RegisterMonitorStreamServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	client := monitorv1.NewMonitorStreamClient(cc)

	secret := mintToken(t, conn, "audit-me", authn.ScopeMonitor)
	ctx, cancel := context.WithCancel(authCtx(context.Background(), secret))
	defer cancel()
	// onSubscribe fires inside the handler, so we just open the stream and wait
	// for the callback rather than blocking on Header() (no headers until a send).
	if _, err := client.Subscribe(ctx, &monitorv1.SubscribeRequest{}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	select {
	case name := <-called:
		if name != "audit-me" {
			t.Fatalf("onSubscribe actor = %q, want audit-me", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onSubscribe was never called")
	}
}
