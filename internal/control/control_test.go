// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package control_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"

	"reflect"

	"github.com/PharosVPN/coxswain/internal/control"
	"github.com/PharosVPN/coxswain/internal/db"
	nodev1 "github.com/PharosVPN/coxswain/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/wg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// recordingNode is a minimal NodeControl server that captures the last
// PushConfig request so a test can assert on the encoded payload.
type recordingNode struct {
	nodev1.UnimplementedNodeControlServer
	lastPush *nodev1.PushConfigRequest
}

func (n *recordingNode) PushConfig(_ context.Context, req *nodev1.PushConfigRequest) (*nodev1.PushConfigResponse, error) {
	n.lastPush = req
	return &nodev1.PushConfigResponse{AppliedRevision: req.GetRevision(), Reloaded: true}, nil
}

// TestPushAmneziaWGConfigRoundTrip verifies the encoding contract for
// PushConfigRequest.config with PROTOCOL_AMNEZIAWG: typed AmneziaWGConfig
// proto bytes carrying the peer set verbatim, no obfuscation, no surprises.
func TestPushAmneziaWGConfigRoundTrip(t *testing.T) {
	rec := &recordingNode{}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	nodev1.RegisterNodeControlServer(srv, rec)
	go srv.Serve(lis) //nolint:errcheck // stops on Stop
	t.Cleanup(srv.Stop)

	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { cc.Close() })
	client := control.NewClientFromConn(cc)

	peers := []*nodev1.Peer{
		{
			Id:           "pee_1",
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    "cGVlci1vbmU=",
			AllowedIps:   []string{"10.86.0.7/32"},
			PresharedKey: "cHNrLW9uZQ==",
			Endpoints:    []string{"203.0.113.7:443"},
		},
		{
			Id:           "pee_2",
			Protocol:     nodev1.Protocol_PROTOCOL_AMNEZIAWG,
			PublicKey:    "cGVlci10d28=",
			AllowedIps:   []string{"10.86.0.8/32"},
			PresharedKey: "cHNrLXR3bw==",
			Endpoints:    []string{"203.0.113.8:443"},
		},
	}
	resp, err := client.PushAmneziaWGConfig(context.Background(), 17, peers)
	if err != nil {
		t.Fatalf("PushAmneziaWGConfig: %v", err)
	}
	if resp.GetAppliedRevision() != 17 {
		t.Errorf("applied revision: got %d want 17", resp.GetAppliedRevision())
	}

	if rec.lastPush == nil {
		t.Fatal("server saw no PushConfig request")
	}
	if rec.lastPush.GetProtocol() != nodev1.Protocol_PROTOCOL_AMNEZIAWG {
		t.Errorf("protocol: got %v", rec.lastPush.GetProtocol())
	}
	if rec.lastPush.GetRevision() != 17 {
		t.Errorf("revision: got %d", rec.lastPush.GetRevision())
	}

	// The wire bytes must decode as the typed message — that's the contract.
	var decoded nodev1.AmneziaWGConfig
	if err := proto.Unmarshal(rec.lastPush.GetConfig(), &decoded); err != nil {
		t.Fatalf("unmarshal AmneziaWGConfig: %v", err)
	}
	if len(decoded.GetPeers()) != len(peers) {
		t.Fatalf("decoded peer count: got %d want %d", len(decoded.GetPeers()), len(peers))
	}
	for i, p := range peers {
		got := decoded.GetPeers()[i]
		if got.GetId() != p.GetId() ||
			got.GetPublicKey() != p.GetPublicKey() ||
			got.GetPresharedKey() != p.GetPresharedKey() ||
			!reflect.DeepEqual(got.GetAllowedIps(), p.GetAllowedIps()) ||
			!reflect.DeepEqual(got.GetEndpoints(), p.GetEndpoints()) {
			t.Errorf("peer %d not round-tripped: got %+v want %+v", i, got, p)
		}
	}
}

func TestAmneziaWGFromStatus(t *testing.T) {
	// A status with no AmneziaWG block — node has not configured its data
	// plane yet.
	if pk, obf := control.AmneziaWGFromStatus(&nodev1.GetStatusResponse{}); pk != "" || !obf.IsZero() {
		t.Errorf("empty status: got (%q, %+v)", pk, obf)
	}

	status := &nodev1.GetStatusResponse{
		Amneziawg: &nodev1.AmneziaWGInfo{
			PublicKey: "node-wg-pub",
			Obfuscation: &nodev1.AmneziaWGObfuscation{
				Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 45, S3: 60, S4: 75,
				H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755,
				I1: "<b 0x00000000>",
			},
		},
	}
	pk, obf := control.AmneziaWGFromStatus(status)
	if pk != "node-wg-pub" {
		t.Errorf("public key: got %q", pk)
	}
	want := wg.Obfuscation{
		Jc: 4, Jmin: 40, Jmax: 70, S1: 30, S2: 45, S3: 60, S4: 75,
		H1: 1515448789, H2: 2406647629, H3: 3604601557, H4: 1124628755,
		I1: "<b 0x00000000>",
	}
	if obf != want {
		t.Errorf("obfuscation: got %+v want %+v", obf, want)
	}
}

// fakeNode is a minimal NodeControl server for exercising the control client.
type fakeNode struct {
	nodev1.UnimplementedNodeControlServer
}

func (fakeNode) GetStatus(context.Context, *nodev1.GetStatusRequest) (*nodev1.GetStatusResponse, error) {
	return &nodev1.GetStatusResponse{AgentVersion: "node 9.9.9", UptimeSeconds: 42}, nil
}

func (fakeNode) AddPeer(_ context.Context, req *nodev1.AddPeerRequest) (*nodev1.PeerResponse, error) {
	return &nodev1.PeerResponse{PeerId: req.GetPeer().GetId(), Applied: true}, nil
}

// TestControlClientOverMTLS dials a fake node server over the full mTLS path:
// coxswain's controller cert vs a Fleet-CA node cert, both chaining to the root.
func TestControlClientOverMTLS(t *testing.T) {
	ctx := context.Background()

	conn, err := db.Open(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	controllerCert, _, err := pki.EnsureControllerCert(ctx, conn, bundle.Fleet)
	if err != nil {
		t.Fatalf("EnsureControllerCert: %v", err)
	}

	// Node server certificate, signed off the Fleet CA with a localhost SAN.
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node-test"}}, nodeKey)
	if err != nil {
		t.Fatalf("node CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	signed, err := pki.SignNodeCSR(bundle.Fleet, csrPEM, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatalf("SignNodeCSR: %v", err)
	}
	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	nodeKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeKeyDER})
	serverCert, err := tls.X509KeyPair(concat(signed.CertPEM, bundle.Fleet.CertPEM), nodeKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(bundle.Root.CertPEM)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
	})))
	nodev1.RegisterNodeControlServer(srv, fakeNode{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(lis) //nolint:errcheck // returns on Stop
	defer srv.Stop()

	dialer, err := control.NewDialer(
		concat(controllerCert.CertPEM, bundle.Fleet.CertPEM),
		controllerCert.KeyPEM,
		bundle.Root.CertPEM)
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	client, err := dialer.Dial(lis.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.GetAgentVersion() != "node 9.9.9" {
		t.Errorf("agent version: got %q", status.GetAgentVersion())
	}

	peerResp, err := client.AddPeer(ctx, &nodev1.Peer{
		Id:        "peer-1",
		Protocol:  nodev1.Protocol_PROTOCOL_AMNEZIAWG,
		PublicKey: "dGVzdA==",
	})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if !peerResp.GetApplied() || peerResp.GetPeerId() != "peer-1" {
		t.Errorf("AddPeer: got %+v", peerResp)
	}
}

func TestNewDialerRejectsBadInput(t *testing.T) {
	if _, err := control.NewDialer([]byte("nope"), []byte("nope"), []byte("nope")); err == nil {
		t.Error("expected NewDialer to reject malformed PEM")
	}
}

// concat joins PEM blocks without aliasing the inputs.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
