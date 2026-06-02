# Control-plane egress relaying — operator guide & validation runbook

coxswain dials **out** to every node — gRPC `NodeControl` (mTLS, :8444) and SSH
(:22, onboarding/update). "Zero inbound" hides coxswain's attack surface, not
its *observability*: anyone watching a public node sees coxswain's egress IP,
which reveals the operator's location and clusters the whole fleet to one pivot.
Control-plane egress relaying (DESIGN §3, decision 19) routes those connections
through one or more enrolled relays, so a node — and any node-side observer —
sees a relay's IP, never coxswain's.

## How it works

- A relay enrolled with `--egress` runs a second `relay egress` process. It is
  **protocol-blind**: coxswain opens a substream and writes a one-line
  `CONNECT host:port`, the relay dials it over raw TCP and pumps bytes. The
  gRPC-mTLS / SSH payload is end-to-end between coxswain and the node, so the
  relay terminates neither — one generic relay carries both control channels.
- coxswain's gRPC and SSH dialers route through the relay automatically whenever
  an active egress relay is enrolled (`grpc.WithContextDialer` /
  `ssh.DialConfig.Dialer`); with none, they dial direct.
- **Chain (≥2 relays):** each hop's mutual-TLS connection is dialed *through* the
  previous hop's tunnel (nested), so `coxswain → relay₁ → … → relayₙ → node`. The
  first relay sees coxswain but only learns the next hop; the last relay reaches
  the node but its peer is the previous relay. **No single relay sees both ends.**
- Chain order is the relays' `egress_hop` (hop 1 closest to coxswain), not
  enrollment time.

## CLI

```sh
# Enrol a relay that also carries control-plane egress (auto-assigns the next hop).
cox relays add <ssh-host> --endpoint <host:8444> --hostname <host> --egress

# Pin an explicit chain position instead of auto-assigning.
cox relays add <ssh-host> --endpoint <host:8444> --hostname <host> --egress --egress-hop 1

# Reorder, or drop a relay from the chain (coxswain stops routing through it).
cox relays set-egress <relay-id> --hop 2
cox relays set-egress <relay-id> --disable

# See the chain: the EGRESS column shows each relay's endpoint + hop.
cox relays list
```

`--hostname` must be the address coxswain will dial (it is signed into the relay
cert as a SAN); coxswain reaches the egress on `<hostname>:8456` by default.

## Validation runbook

With one or more egress relays enrolled, drive any control-plane command (e.g.
`cox nodes status <node>`) and confirm the node sees only the **last** relay:

```sh
# On the node — who connects to the gRPC port? (expect the last hop's IP)
tcpdump -nni any "tcp port 8444 and host <relay-ip>"

# SSH source after enrolment (expect a relay IP, never coxswain's):
journalctl _COMM=sshd | grep "Accepted publickey"
```

On each relay, `journalctl -u relay-egress | grep "coxswain connected"` shows
its *inbound* peer: the first hop sees coxswain's IP; every later hop sees the
*previous* relay's IP, not coxswain's. Reordering hops (`set-egress --hop`)
reverses these sources — confirmed live across a NYC → Frankfurt → SFO chain.

> Capture tip: `tcp[tcpflags] & tcp-syn` mis-evaluates on `tcpdump -i any`
> (cooked/LINUX_SLL2). Use a plain `host`/`port` filter.

## Scope

- **v1 ladder:** (1) a single relay hides coxswain from nodes; (2) a fixed
  N-relay chain so no single relay sees both ends. Both shipped.
- **Irreducible leak:** the first relay sees coxswain's IP. Mitigate
  operationally — run it on a disposable VPS, or send coxswain's first hop over
  Tor. Closing it in-protocol is ladder step 3 (onion routing), deferred.
- **No HA:** a control-plane outage is survivable (nodes keep serving from
  persisted state), so the egress path needs no redundancy. A dead tunnel is
  re-dialed lazily on the next command.

## Automated coverage

`internal/egress` covers the protocol-blind CONNECT codec, the single-hop tunnel
(incl. lazy reconnect), and a two-hop chain over mutual TLS at each hop
(`TestChainTwoHops`). `internal/fleet` round-trips the `egress_endpoint` /
`egress_hop` relay fields.
