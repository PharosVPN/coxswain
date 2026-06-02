# coxswain — Build Brief

**Read first:** `docs/BUILD.md`, then `docs/DESIGN.md`. This brief assumes both.

`coxswain` is the **core** project — built collaboratively (operator + Claude), not
delegated to a subagent. This file is the roadmap, not a hand-off spec.

---

## Scope

`coxswain` is the controller. It owns: fleet state, the CA, cloud provisioning, the
outbound control loop to `node` nodes, the embedded `relay` relay + remote-relay
dialer, the account/sync service, and the admin Web UI.

It does **not** run a data plane and opens **no inbound ports**.

## Prior art to port

The current `amnezia-travelvpn` repo (`/Users/khalefa/Projects/amnezia-travelvpn`)
is a working single-controller version. Port forward, do not copy blindly:

- **Keep:** SQLite + Goose migrations, YAML snapshot projections, JWT + Argon2id
  auth, the koanf config loader, the AmneziaWG/XRay profile model, the
  embedded-SvelteKit pattern.
- **Replace:** SSH-to-node *control* and shell config-editing → outbound
  mTLS/gRPC to `node`. SSH is kept, but only as the agent install/update
  channel — never for control.
- **Add:** the CA/PKI, account system (users as auth principals), E2E profile
  encryption, live event streaming + WebSocket, optimistic concurrency, the
  embedded `relay`, `.pharos` export.

## Milestones

| # | Milestone | Output |
|---|---|---|
| M1 | Skeleton | `cmd/cox`, config, SQLite + migrations, CA generation on first run, `cox init --personal/--enterprise` |
| M2 | Node onboarding | SSH agent install/update; `cox nodes add` — CSR signing, host-key pinning, `cox ssh-key` |
| M3 | Control loop | gRPC client to `node`; push config, push/revoke peers; status/metrics |
| M4 | Live plane | consume `node` event stream; WebSocket fan-out to admin browsers |
| M5 | Admin UI | SvelteKit SPA, auth, fleet/users/peers/admins screens, optimistic concurrency (409 on stale write) |
| M6 | Accounts & sync | users as auth principals + roles; E2E profile encryption (§8); embedded `relay`; remote-`relay` reverse-tunnel dialer |
| M7 | Distribution | `.pharos` export (all `enc` modes), enrollment-ticket QR |

> The Amnezia-compat `.vpn` export originally planned for M7 was dropped: a
> `.vpn` file embeds the device's WireGuard private key in plaintext, which is
> incompatible with coxswain's E2E "ciphertext only" guarantee (§8). `caravel`
> consumes `.pharos` profiles directly.

### Planned — node cascade / multi-hop (DESIGN decision 18, not scheduled)

A post-M7 feature: `client → entry node → inner AmneziaWG link → exit node →
internet`, with `coxswain` as the sole mesh coordinator (it already holds every
node's AmneziaWG public key via `GetStatus`). Not scheduled and no proto yet —
but as the fleet/control/netpolicy models grow, keep them open to it:

- a `node_links` projection (the admin-defined `node`↔`node` edge graph;
  `version` + `updated_at` like every row);
- per-device routing in the control client — binding a client peer to an exit,
  re-bindable **live** (an exit-switch is a server-side route flip, no profile
  change), so don't model a device's egress as a fixed property of its node;
- the exit-selection call rides the existing `caravel → relay → coxswain` control
  channel (§8) — it is *not* signalled in-band through the tunnel.

The `NodeControl` route-binding RPC this needs is deliberately unspecified here;
it will be designed with `node`'s build when the feature is scheduled.

## Contracts `coxswain` owns

`coxswain` defines the wire contracts the other repos consume. As each milestone
lands, update `docs/proto/`:

- `node` control service (M3) + event stream (M4)
- `relay` reverse-tunnel + relayed client service (M6)
- `caravel` account/sync service (M6/M7)

Coordinate every proto change with the dependent subproject's BUILD.

### Pinned `relay` ↔ `coxswain` identifiers

Confirmed with the `relay` agent during its R1. The M6b relayed-client proto
and PKI **must** use these exact values:

| Role | Value |
|---|---|
| Injected verified-device-fingerprint metadata key | `x-pharos-device-fp` |
| Stripped client-metadata prefix (anti-spoofing) | `x-pharos-` |
| Backend delegation cert `Organization` | `PharosVPN Relay` |
| `coxswain` gRPC-leg leaf `CN` / backend SNI | `coxswain-grpc` |
| Relay certificate | one Fleet-CA leaf, `ServerAuth` + `ClientAuth` EKU |

### Relay enrollment contract (relay R5)

`coxswain` enrols a remote `relay` relay over SSH, exactly as it onboards a `node`
node (DESIGN §5, decision 14 — CSR-over-SSH, **no bootstrap token**). SSH is an
install/enrol channel only; once enrolled, `coxswain` reaches the relay solely by
dialling **out** to its reverse-tunnel listener — the relay opens no path back.

**Binary & on-host layout**

| | |
|---|---|
| Binary path | `/usr/local/bin/relay` |
| Config / cert dir | `/etc/relay` |
| systemd unit | `/etc/systemd/system/relay.service` — `ExecStart=/usr/local/bin/relay run --config-dir /etc/relay` |

**Command surface** — `coxswain`'s relay-deploy invokes these, mirroring `node`:

| Command | Behaviour |
|---|---|
| `relay gen-csr` | Generate the relay keypair **on the host** and print a PKCS#10 CSR (PEM) to stdout. The private key never leaves the host. |
| `relay version` | Print the installed version to stdout. |
| `relay run --config-dir /etc/relay` | Run the relay (systemd `ExecStart`). |

**CSR & signing** — `relay gen-csr` emits a *plain* CSR carrying only the
public key; its subject and SANs are ignored. `coxswain` is the sole authority on
the relay's identity and **overrides** them when it signs off the Fleet CA:

- Subject `O = PharosVPN Relay` — the pinned delegation marker (table above).
  A relay host may not self-assert it; only `coxswain` grants it.
- EKU = `ServerAuth` + `ClientAuth` — one dual-EKU leaf.
- DNS SAN = the relay's **public client-endpoint hostname**, set by `coxswain` from
  the configured `relay.public_endpoint`. `relay gen-csr` takes no
  `--hostname` flag — `coxswain` owns the hostname.

**Files `coxswain` pushes back over SSH** after signing:

| Path | Mode | Contents |
|---|---|---|
| `/etc/relay/relay.crt` | 0644 | Relay leaf + Fleet intermediate, in chain order. |
| `/etc/relay/fleet-ca.crt` | 0644 | Fleet CA cert — verifies `coxswain`'s gRPC-leg cert (`BackendTrustPEM`). |
| `/etc/relay/device-ca.crt` | 0644 | Device CA cert — verifies caravel client leaves (`ClientTrustPEM`). |

The relay private key stays on the host (`relay gen-csr` wrote it next to the
config dir); `coxswain` never sees it.

## Non-negotiables

- No inbound ports. All node/relay connections are coxswain-initiated.
- The CA private key never leaves `coxswain`'s SQLite.
- User private keys exist on `coxswain` only as passphrase-wrapped blobs (DESIGN §8).
- Every mutable table row has `version` + `updated_at` (DESIGN §7).
