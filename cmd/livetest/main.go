// Command livetest is a throwaway helper for driving the live cloud fleet:
// it enrolls a user's e2e encryption key (the client side normally does this),
// and decrypts the issued account-mode profile into an awg-quick conf so a plain
// AmneziaWG client can verify the data plane. NOT shipped.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/db"
	"github.com/PharosVPN/coxswain/internal/e2e"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/profile"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "livetest:", err)
		os.Exit(1)
	}
}

type obf struct {
	Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4 uint32
	I1, I2, I3, I4, I5                             string
}

type awgParams struct {
	PrivateKey   string `json:"private_key"`
	Address      string `json:"address"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Endpoints    []struct {
		IP string `json:"ip"`
	} `json:"endpoints"`
	Obfuscation obf `json:"obfuscation"`
}

func main() {
	if len(os.Args) < 2 {
		must(fmt.Errorf("usage: livetest enroll <db> <userID> <pass> | conf <db> <userID> <pass> <nodeName> [port]"))
	}
	ctx := context.Background()
	open := func(p string) *sql.DB { c, e := db.Open(p); must(e); return c }

	switch os.Args[1] {
	case "enroll":
		conn := open(os.Args[2])
		kp, err := e2e.GenerateKeyPair()
		must(err)
		wrapped, err := e2e.WrapPrivateKey(os.Args[4], kp.Private)
		must(err)
		must(account.SetEncryptionKey(ctx, conn, os.Args[3], kp.Public, wrapped))
		fmt.Println("enrolled e2e encryption key for", os.Args[3])

	case "conf":
		conn := open(os.Args[2])
		userID, pass, nodeName := os.Args[3], os.Args[4], os.Args[5]
		port := "443"
		if len(os.Args) > 6 {
			port = os.Args[6]
		}
		_, wrapped, err := account.GetEncryptionKey(ctx, conn, userID)
		must(err)
		priv, err := e2e.UnwrapPrivateKey(pass, wrapped)
		must(err)
		signer, _, err := profile.EnsureSigningKey(ctx, conn)
		must(err)
		ct, _, err := profile.LatestCiphertext(ctx, conn, userID, "")
		must(err)
		var bundle e2e.SealedBundle
		must(json.Unmarshal(ct, &bundle))
		plain, err := e2e.Open(bundle, priv, ed25519.PublicKey(signer.Public))
		must(err)
		var prof profile.Profile
		must(json.Unmarshal(plain, &prof))

		var p awgParams
		found := false
		for _, n := range prof.Nodes {
			if n.Name != nodeName {
				continue
			}
			for _, pr := range n.Protocols {
				if pr.Type == "amneziawg" {
					must(json.Unmarshal(pr.Params, &p))
					found = true
				}
			}
		}
		if !found || len(p.Endpoints) == 0 {
			must(fmt.Errorf("node %q not found in profile (or no endpoints)", nodeName))
		}

		var b strings.Builder
		b.WriteString("[Interface]\n")
		fmt.Fprintf(&b, "PrivateKey = %s\n", p.PrivateKey)
		fmt.Fprintf(&b, "Address = %s\n", p.Address)
		b.WriteString("DNS = 1.1.1.1\n")
		o := p.Obfuscation
		for _, kv := range []struct {
			k string
			v uint32
		}{{"Jc", o.Jc}, {"Jmin", o.Jmin}, {"Jmax", o.Jmax}, {"S1", o.S1}, {"S2", o.S2}, {"S3", o.S3}, {"S4", o.S4}, {"H1", o.H1}, {"H2", o.H2}, {"H3", o.H3}, {"H4", o.H4}} {
			fmt.Fprintf(&b, "%s = %d\n", kv.k, kv.v)
		}
		for i, t := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
			if t != "" {
				fmt.Fprintf(&b, "I%d = %s\n", i+1, t)
			}
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "Endpoint = %s:%s\n", p.Endpoints[0].IP, port)
		b.WriteString("AllowedIPs = 0.0.0.0/0\n")
		b.WriteString("PersistentKeepalive = 25\n")
		fmt.Print(b.String())

	case "pharos":
		// pharos <db> <userID> <pass> <deviceID|-> [nodeName] → a plaintext
		// (none-mode) .pharos the Mac app can import directly. deviceID selects a
		// per-device sealed profile; "-" means the legacy device-less profile.
		// Endpoint ports are pinned to 443 (the node's real awg0 listen port)
		// since the decision-17 range isn't dialable.
		conn := open(os.Args[2])
		userID, pass, deviceID := os.Args[3], os.Args[4], os.Args[5]
		if deviceID == "-" {
			deviceID = ""
		}
		nodeFilter := ""
		if len(os.Args) > 6 {
			nodeFilter = os.Args[6]
		}
		_, wrapped, err := account.GetEncryptionKey(ctx, conn, userID)
		must(err)
		priv, err := e2e.UnwrapPrivateKey(pass, wrapped)
		must(err)
		signer, _, err := profile.EnsureSigningKey(ctx, conn)
		must(err)
		ct, _, err := profile.LatestCiphertext(ctx, conn, userID, deviceID)
		must(err)
		var bundle e2e.SealedBundle
		must(json.Unmarshal(ct, &bundle))
		plain, err := e2e.Open(bundle, priv, ed25519.PublicKey(signer.Public))
		must(err)
		var prof profile.Profile
		must(json.Unmarshal(plain, &prof))

		var nodes []profile.Node
		for _, n := range prof.Nodes {
			if nodeFilter != "" && n.Name != nodeFilter {
				continue
			}
			for i := range n.Protocols {
				if n.Protocols[i].Type == "amneziawg" {
					n.Protocols[i].Params = pinPort443(n.Protocols[i].Params)
				}
			}
			nodes = append(nodes, n)
		}
		prof.Nodes = nodes
		payload, err := json.Marshal(prof)
		must(err)
		fmt.Printf(`{"fmt":"pharos-profile","v":1,"enc":"none","payload":%s}`+"\n", payload)

	case "endpoints":
		// endpoints <db> <nodeID> <ip1,ip2,...> — set a node's endpoint IP pool
		// (decision 17), which the issued profiles then carry for random entry.
		conn := open(os.Args[2])
		node, err := fleet.GetNode(ctx, conn, os.Args[3])
		must(err)
		node.EndpointIPs = strings.Split(os.Args[4], ",")
		_, err = fleet.UpdateNode(ctx, conn, node)
		must(err)
		fmt.Println("endpoint pool for", node.ID, "=", node.EndpointIPs)

	default:
		must(fmt.Errorf("unknown subcommand %q", os.Args[1]))
	}
}

// pinPort443 rewrites every amneziawg endpoint's port range to a single port 443
// (the node's real awg0 listen port) so a client dials the right port.
func pinPort443(params json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(params, &m) != nil {
		return params
	}
	if eps, ok := m["endpoints"].([]any); ok {
		for _, ep := range eps {
			if e, ok := ep.(map[string]any); ok {
				e["port_min"] = 443
				e["port_max"] = 443
			}
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return params
	}
	return out
}
