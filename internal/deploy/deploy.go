// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package deploy onboards nodes and relays over SSH (DESIGN §5):
// it installs the agent, signs its certificate request, and starts it. SSH is
// used only to install and update the agent — all node control is gRPC, and a
// relay is reached by dialling out to its reverse tunnel.
package deploy

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/idgen"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// ControlPort is the port a node listens on for coxswain's gRPC control plane.
const ControlPort = 8444

// On-node layout and the coxswain↔node CLI contract. These are confirmed against
// node/BUILD.md when that repo lands.
const (
	nodeBinaryPath = "/usr/local/bin/node"
	caCertPath     = "/etc/node/ca.crt"
	nodeCertPath   = "/etc/node/node.crt"
	unitPath       = "/etc/systemd/system/node.service"

	// cmdGenCSR makes node generate its keypair on the node and print a CSR.
	cmdGenCSR = nodeBinaryPath + " gen-csr"
	// cmdVersion prints the installed agent version.
	cmdVersion = nodeBinaryPath + " version"
)

const systemdUnit = `[Unit]
Description=PharosVPN node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + nodeBinaryPath + ` run --config-dir /etc/node
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// Remote is an established connection to a node. *ssh.Conn satisfies it.
type Remote interface {
	Run(ctx context.Context, cmd string, stdin []byte) ([]byte, error)
	Upload(ctx context.Context, remotePath string, data []byte, mode fs.FileMode) error
	HostKey() string
	Close() error
}

// InstallSpec says how to place the node binary on a node. Exactly one of
// Binary or URL must be set.
type InstallSpec struct {
	// Binary is uploaded directly over the SSH channel.
	Binary []byte
	// URL is fetched by the node itself over HTTP.
	URL string
}

func (s InstallSpec) validate() error {
	switch {
	case len(s.Binary) == 0 && s.URL == "":
		return fmt.Errorf("deploy: install needs a binary or a URL")
	case len(s.Binary) > 0 && s.URL != "":
		return fmt.Errorf("deploy: install needs exactly one of binary or URL")
	default:
		return nil
	}
}

// AddParams are the inputs to AddNode.
type AddParams struct {
	Name     string // generated from Region if empty
	Region   string // required
	SSHHost  string // required — used both to dial and as a cert SAN
	SSHUser  string
	SSHPort  int
	ServerID string // optional — the server this node is deployed onto
	Install  InstallSpec
}

// AddResult reports what onboarding produced.
type AddResult struct {
	Node         fleet.Node
	NodeCertID   string
	AgentVersion string
}

// AddNode installs the node agent on an already-connected node, signs its
// certificate, and starts the service. On failure the node record is left
// with status "error".
func AddNode(ctx context.Context, db *sql.DB, remote Remote, bundle pki.Bundle, p AddParams) (AddResult, error) {
	if p.Region == "" {
		return AddResult{}, fmt.Errorf("deploy: region is required")
	}
	if p.SSHHost == "" {
		return AddResult{}, fmt.Errorf("deploy: ssh host is required")
	}
	if err := p.Install.validate(); err != nil {
		return AddResult{}, err
	}

	name := p.Name
	if name == "" {
		name = generateName(p.Region)
	}

	node, err := fleet.CreateNode(ctx, db, fleet.Node{
		Name:       name,
		Region:     p.Region,
		PublicIP:   p.SSHHost,
		SSHHost:    p.SSHHost,
		SSHUser:    p.SSHUser,
		SSHPort:    p.SSHPort,
		SSHHostKey: remote.HostKey(),
		ServerID:   p.ServerID,
		Status:     fleet.StatusProvisioning,
	})
	if err != nil {
		return AddResult{}, err
	}

	res, err := onboard(ctx, db, remote, bundle, &node, p)
	if err != nil {
		markFailed(ctx, db, node)
		return AddResult{}, err
	}
	return res, nil
}

// onboard runs the install/sign/start sequence against an existing node record.
func onboard(ctx context.Context, db *sql.DB, remote Remote, bundle pki.Bundle, node *fleet.Node, p AddParams) (AddResult, error) {
	if err := installBinary(ctx, remote, p.Install, nodeBinaryPath); err != nil {
		return AddResult{}, err
	}

	// node generates its keypair on the node and returns a CSR; the node's
	// private key never crosses to coxswain.
	csrPEM, err := remote.Run(ctx, cmdGenCSR, nil)
	if err != nil {
		return AddResult{}, fmt.Errorf("deploy: node gen-csr: %w", err)
	}

	var extraIPs []net.IP
	var extraDNS []string
	if ip := net.ParseIP(p.SSHHost); ip != nil {
		extraIPs = []net.IP{ip}
	} else {
		extraDNS = []string{p.SSHHost}
	}
	signed, err := pki.SignNodeCSR(bundle.Fleet, csrPEM, extraIPs, extraDNS)
	if err != nil {
		return AddResult{}, err
	}
	certID, err := pki.RecordNodeCert(ctx, db, node.ID, signed)
	if err != nil {
		return AddResult{}, err
	}

	// node.crt carries the leaf plus the Fleet intermediate so node can
	// present a full chain; ca.crt is the root trust anchor.
	nodeChain := append(append([]byte{}, signed.CertPEM...), bundle.Fleet.CertPEM...)
	if err := remote.Upload(ctx, nodeCertPath, nodeChain, 0o644); err != nil {
		return AddResult{}, err
	}
	if err := remote.Upload(ctx, caCertPath, bundle.Root.CertPEM, 0o644); err != nil {
		return AddResult{}, err
	}

	if err := remote.Upload(ctx, unitPath, []byte(systemdUnit), 0o644); err != nil {
		return AddResult{}, err
	}
	if _, err := remote.Run(ctx, "systemctl daemon-reload && systemctl enable --now node", nil); err != nil {
		return AddResult{}, fmt.Errorf("deploy: start node service: %w", err)
	}

	agentVersion := readVersion(ctx, remote, cmdVersion)

	node.ControlAddr = net.JoinHostPort(p.SSHHost, strconv.Itoa(ControlPort))
	node.AgentVersion = agentVersion
	node.Status = fleet.StatusActive
	updated, err := fleet.UpdateNode(ctx, db, *node)
	if err != nil {
		return AddResult{}, err
	}

	return AddResult{Node: updated, NodeCertID: certID, AgentVersion: agentVersion}, nil
}

// UpdateAgent re-installs the node binary on a node and restarts the service.
func UpdateAgent(ctx context.Context, db *sql.DB, remote Remote, node fleet.Node, spec InstallSpec) (fleet.Node, error) {
	if err := spec.validate(); err != nil {
		return fleet.Node{}, err
	}
	if err := installBinary(ctx, remote, spec, nodeBinaryPath); err != nil {
		return fleet.Node{}, err
	}
	if _, err := remote.Run(ctx, "systemctl restart node", nil); err != nil {
		return fleet.Node{}, fmt.Errorf("deploy: restart node: %w", err)
	}
	node.AgentVersion = readVersion(ctx, remote, cmdVersion)
	return fleet.UpdateNode(ctx, db, node)
}

// Service starts or stops the node service on a node. action is "start" or
// "stop".
func Service(ctx context.Context, remote Remote, action string) error {
	switch action {
	case "start", "stop":
	default:
		return fmt.Errorf("deploy: unknown service action %q", action)
	}
	if _, err := remote.Run(ctx, "systemctl "+action+" node", nil); err != nil {
		return fmt.Errorf("deploy: %s node: %w", action, err)
	}
	return nil
}

func installBinary(ctx context.Context, remote Remote, spec InstallSpec, binaryPath string) error {
	if len(spec.Binary) > 0 {
		return remote.Upload(ctx, binaryPath, spec.Binary, 0o755)
	}
	cmd := fmt.Sprintf("curl -fsSL %s -o %s && chmod +x %s",
		shellQuote(spec.URL), binaryPath, binaryPath)
	if _, err := remote.Run(ctx, cmd, nil); err != nil {
		return fmt.Errorf("deploy: download binary: %w", err)
	}
	return nil
}

// readVersion best-effort reads an installed agent's version via versionCmd.
func readVersion(ctx context.Context, remote Remote, versionCmd string) string {
	out, err := remote.Run(ctx, versionCmd, nil)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func markFailed(ctx context.Context, db *sql.DB, node fleet.Node) {
	node.Status = fleet.StatusError
	_, _ = fleet.UpdateNode(ctx, db, node)
}

func generateName(region string) string {
	suffix := strings.TrimPrefix(idgen.New("n"), "n_")
	return fmt.Sprintf("node-%s-%s", region, suffix[:6])
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
