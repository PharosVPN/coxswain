# Node cascade (multi-hop) — operator guide & validation runbook

Node cascade routes a device's tunnel across **two** of your nodes before the
internet: `client → entry → [inner AmneziaWG link] → exit → internet`
(DESIGN §3, decision 18). The entry sees the client's address but not its
destination; the exit sees the destination but not the client; **no single node
sees both ends**. coxswain is the sole coordinator — the client only ever
handshakes with, and holds credentials for, its **entry**.

## How it works

- **Inner link.** The entry node runs a second AmneziaWG interface (`awgN`) that
  dials the exit's public endpoint, reusing the entry's own keypair but adopting
  the **exit's** obfuscation so the handshake matches. The exit treats the entry
  as an ordinary forwarded + masqueraded peer — it needs no new concept.
- **Transit.** For a cascaded device the entry does **not** masquerade to its own
  egress; it policy-routes that device's tunnel IP into the inner interface
  (mangle `MARK` + `ip rule` + `ip route`). Transited packets leave via `awgN`,
  so the egress masquerade never matches them — the exit NATs them.
- **Exit-switch** is a live server-side route flip on the entry: same profile,
  no client re-handshake. Switching *entry* is the only move that re-establishes
  the tunnel.

## CLI

```sh
# Define the graph: an inner link from an entry node to an exit node.
cox links add  <entry-node-id> <exit-node-id>
cox links list
cox links rm   <link-id>

# Route a device's traffic (arriving at <entry>) to egress via <exit>.
# Re-run with a different exit to switch live.
cox device set-exit   <device-id> <entry-node-id> <exit-node-id>
cox device clear-exit <device-id>
```

Both nodes must be enrolled and have reported their AmneziaWG identity
(`cox nodes status`), and the exit must have a public endpoint. The device must
already have a tunnel (peer) on the entry node.

## Two-node validation runbook

Prerequisites: two enrolled node nodes (`entry`, `exit`) reachable by coxswain,
one device with a profile pinned to `entry`, and a real AmneziaWG client.

1. **Confirm both nodes' identities are cached.**
   ```sh
   cox nodes status <entry-id>
   cox nodes status <exit-id>
   ```

2. **Baseline egress (no cascade).** Connect the client (it handshakes with
   `entry`) and check the egress IP:
   ```sh
   curl -s https://ifconfig.me      # → entry's public IP
   ```

3. **Create the inner link and bind the device.**
   ```sh
   cox links add <entry-id> <exit-id>          # note the link id + awgN
   cox device set-exit <device-id> <entry-id> <exit-id>
   ```

4. **Verify the egress moved to the exit — with no reconnect.** Without
   touching the client:
   ```sh
   curl -s https://ifconfig.me      # → EXIT's public IP now
   ```

5. **Verify split knowledge** (on the nodes):
   - On `entry`: `awg show awgN` shows a handshake with the exit; the device's
     traffic counters climb on `awgN`, not on the egress NAT.
   - On `exit`: `awg show awg0` shows the **entry** as a peer whose `allowed-ips`
     contains the device's `/32`; `iptables -t nat -vL POSTROUTING` shows the
     masquerade hits on the exit.
   - On `entry`: `ip rule` shows the `fwmark → table` rule and
     `ip route show table <id>` shows `default dev awgN`.

6. **Live exit-switch.** Point the device at a different exit and re-check egress
   — the client never re-handshakes:
   ```sh
   cox device set-exit <device-id> <entry-id> <other-exit-id>
   curl -s https://ifconfig.me      # → other exit's IP
   ```

7. **Tear down.**
   ```sh
   cox device clear-exit <device-id>            # egress returns to entry
   cox links rm <link-id>                        # awgN removed on the entry
   ```

## Scope

This is the 2-hop path (one inner link). Deeper chains (3 hops, MTU-gated ≥ 1280)
and a NAT'd exit reached via the relay reverse tunnel are future work; the
contract and the inner-link/transit machinery are built to extend to them.

## Automated coverage

The control-plane wiring is covered without two live VMs:
- `coxswain/internal/cascade` tests drive provisioning, bind/switch/clear and
  teardown against a fake fleet, asserting the exact `ConfigureInnerLink`,
  `AddPeer`, `RemovePeer` and `SetNetworkConfig` calls.
- `node` tests (`internal/control`, `internal/awg`, `internal/netpolicy`) prove
  the node applies an inner link and per-device transit routes.
- The transit rule strings are pinned **identically** in
  `coxswain/internal/netpolicy` and `node/internal/netpolicy`, so the admin-UI
  preview matches what the node applies.
